use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use aya::{
    maps::{MapData, RingBuf},
    programs::{KProbe, TracePoint},
    Ebpf,
};
use serde_json::{json, Value};
use snoop_common::{
    SensorEvent, EVENT_KIND_CONNECT, EVENT_KIND_EXECVE, EVENT_KIND_EXIT, EVENT_KIND_OPENAT,
    PROTO_TCP, PROTO_UDP, SENSOR_AF_INET, SENSOR_AF_INET6,
};

#[derive(Clone, Debug)]
pub struct SensorConfig {
    pub run_id: String,
    pub sample_id: String,
    pub files_log: PathBuf,
    pub proc_log: PathBuf,
    pub network_log: Option<PathBuf>,
    pub canary_catalog: Option<PathBuf>,
    pub canary_mount: String,
    pub target_cgroup_id: Option<u64>,
    pub container_id: Option<String>,
    pub duration: Duration,
}

impl SensorConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = String>,
    {
        let mut run_id = std::env::var("EXFIL_RUN_ID").unwrap_or_else(|_| "unknown-run".into());
        let mut sample_id =
            std::env::var("EXFIL_SAMPLE_ID").unwrap_or_else(|_| "unknown-sample".into());
        let mut files_log = std::env::var("EXFIL_FILES_LOG").ok().map(PathBuf::from);
        let mut proc_log = std::env::var("EXFIL_PROC_LOG").ok().map(PathBuf::from);
        let mut network_log = std::env::var("EXFIL_NETWORK_LOG")
            .ok()
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let mut canary_catalog = std::env::var("EXFIL_CANARY_CATALOG")
            .ok()
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let mut canary_mount =
            std::env::var("EXFIL_CANARY_MOUNT").unwrap_or_else(|_| "/canary".into());
        let mut target_cgroup_id = std::env::var("EXFIL_TARGET_CGROUP_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u64>())
            .transpose()?;
        let mut container_id = std::env::var("EXFIL_CONTAINER_ID")
            .ok()
            .filter(|value| !value.is_empty());
        let mut duration = Duration::from_millis(5000);

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--sensor" => {}
                "--run-id" => run_id = require_arg(&mut iter, "--run-id")?,
                "--sample-id" => sample_id = require_arg(&mut iter, "--sample-id")?,
                "--files-log" => {
                    files_log = Some(PathBuf::from(require_arg(&mut iter, "--files-log")?))
                }
                "--proc-log" => {
                    proc_log = Some(PathBuf::from(require_arg(&mut iter, "--proc-log")?))
                }
                "--network-log" => {
                    network_log = Some(PathBuf::from(require_arg(&mut iter, "--network-log")?))
                }
                "--canary-catalog" => {
                    canary_catalog =
                        Some(PathBuf::from(require_arg(&mut iter, "--canary-catalog")?));
                }
                "--canary-mount" => canary_mount = require_arg(&mut iter, "--canary-mount")?,
                "--target-cgroup-id" => {
                    target_cgroup_id =
                        Some(require_arg(&mut iter, "--target-cgroup-id")?.parse::<u64>()?);
                }
                "--container-id" => container_id = Some(require_arg(&mut iter, "--container-id")?),
                "--duration-ms" => {
                    duration =
                        Duration::from_millis(require_arg(&mut iter, "--duration-ms")?.parse()?);
                }
                other => return Err(format!("unknown sensor argument: {other}").into()),
            }
        }

        Ok(Self {
            run_id,
            sample_id,
            files_log: files_log.ok_or("EXFIL_FILES_LOG or --files-log is required")?,
            proc_log: proc_log.ok_or("EXFIL_PROC_LOG or --proc-log is required")?,
            network_log,
            canary_catalog,
            canary_mount,
            target_cgroup_id,
            container_id,
            duration,
        })
    }
}

fn require_arg<I>(iter: &mut I, flag: &str) -> Result<String, Box<dyn Error>>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

#[derive(Clone, Debug, Default)]
pub struct CanaryPathMatcher {
    paths: Vec<String>,
}

impl CanaryPathMatcher {
    pub fn from_catalog_path(path: &Path, mount_prefix: &str) -> Result<Self, Box<dyn Error>> {
        let text = fs::read_to_string(path)?;
        let value: Value = serde_json::from_str(&text)?;
        let catalog_dir = path.parent().unwrap_or_else(|| Path::new(""));
        let mut matcher = Self::default();
        if let Some(secrets) = value.get("secrets").and_then(Value::as_array) {
            for secret in secrets {
                if let Some(path_value) = secret.get("path").and_then(Value::as_str) {
                    matcher.push_path(path_value.to_string());
                    if let Ok(relative) = Path::new(path_value).strip_prefix(catalog_dir) {
                        let mounted = Path::new(mount_prefix).join(relative);
                        matcher.push_path(mounted.to_string_lossy().into_owned());
                    }
                }
            }
        }
        Ok(matcher)
    }

    fn push_path(&mut self, path: String) {
        if !self.paths.iter().any(|item| item == &path) {
            self.paths.push(path);
        }
    }

    pub fn is_canary(&self, path: &str) -> bool {
        self.paths.iter().any(|item| item == path)
    }
}

#[cfg(target_os = "linux")]
pub fn run_sensor(config: SensorConfig, ebpf_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let bytes = if let Ok(path) = std::env::var("SNOOP_EBPF_OBJ") {
        fs::read(path)?
    } else {
        ebpf_bytes.to_vec()
    };
    if bytes.is_empty() {
        return Err(
            "embedded eBPF object is empty; set SNOOP_EBPF_OBJ or unset SNOOP_SKIP_EBPF_BUILD"
                .into(),
        );
    }

    let matcher = match &config.canary_catalog {
        Some(path) => CanaryPathMatcher::from_catalog_path(path, &config.canary_mount)?,
        None => CanaryPathMatcher::default(),
    };

    let mut ebpf = Ebpf::load(&bytes)?;
    attach_tracepoint(&mut ebpf, "sys_enter_openat", "raw_syscalls", "sys_enter")?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exec",
        "sched",
        "sched_process_exec",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    attach_kprobe(&mut ebpf, "net_enter_sys_connect", "__sys_connect")?;
    attach_kprobe(&mut ebpf, "net_exit_sys_connect", "__sys_connect")?;

    let map = ebpf
        .take_map("EVENTS")
        .ok_or("EVENTS ring buffer not found")?;
    let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(map)?;
    let mut files = open_jsonl(&config.files_log)?;
    let mut procs = open_jsonl(&config.proc_log)?;
    let mut network = match &config.network_log {
        Some(path) => Some(open_jsonl(path)?),
        None => None,
    };

    let deadline = std::time::Instant::now() + config.duration;
    while std::time::Instant::now() < deadline {
        while let Some(item) = ring_buf.next() {
            if item.len() < std::mem::size_of::<SensorEvent>() {
                continue;
            }
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const SensorEvent) };
            if !event_in_scope(&event, config.target_cgroup_id) {
                continue;
            }
            match event.kind {
                EVENT_KIND_OPENAT => {
                    let value = render_file_event(&event, &config, &matcher);
                    write_json_line(&mut files, &value)?;
                }
                EVENT_KIND_EXECVE | EVENT_KIND_EXIT => {
                    let value = render_proc_event(&event, &config);
                    write_json_line(&mut procs, &value)?;
                }
                EVENT_KIND_CONNECT => {
                    if let Some(writer) = network.as_mut() {
                        let value = render_network_event(&event, &config);
                        write_json_line(writer, &value)?;
                    }
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    files.flush()?;
    procs.flush()?;
    if let Some(writer) = network.as_mut() {
        writer.flush()?;
    }
    drop(ebpf);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_sensor(_config: SensorConfig, _ebpf_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    Err("BPF sensor is Linux-only".into())
}

#[cfg(target_os = "linux")]
fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> Result<(), Box<dyn Error>> {
    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/loader.rs:81
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| format!("program `{program_name}` not found"))?
        .try_into()?;
    program.load()?;
    program.attach(category, tracepoint)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn attach_kprobe(
    ebpf: &mut Ebpf,
    program_name: &str,
    function: &str,
) -> Result<(), Box<dyn Error>> {
    // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-0.13.1/src/programs/kprobe.rs:76
    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| format!("program `{program_name}` not found"))?
        .try_into()?;
    program.load()?;
    program.attach(function, 0)?;
    Ok(())
}

fn open_jsonl(path: &Path) -> Result<BufWriter<File>, Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(BufWriter::new(file))
}

fn write_json_line(writer: &mut BufWriter<File>, value: &Value) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub fn event_in_scope(event: &SensorEvent, target_cgroup_id: Option<u64>) -> bool {
    match target_cgroup_id {
        Some(0) | None => true,
        Some(target) => event.cgroup_id == target,
    }
}

pub fn render_file_event(
    event: &SensorEvent,
    config: &SensorConfig,
    matcher: &CanaryPathMatcher,
) -> Value {
    let path = bytes_to_string(event.path_bytes());
    json!({
        "ts": rfc3339_now(),
        "run_id": config.run_id,
        "sample_id": config.sample_id,
        "pid": event.pid,
        "tgid": event.tgid,
        "comm": bytes_to_string(event.comm_bytes()),
        "path": path,
        "is_canary": matcher.is_canary(&path),
        "container_id": config.container_id,
        "cgroup_id": cgroup_json(event.cgroup_id),
    })
}

pub fn render_proc_event(event: &SensorEvent, config: &SensorConfig) -> Value {
    let exe = bytes_to_string(event.exe_bytes());
    let exe_value = if exe.is_empty() {
        proc_exe(event.pid)
    } else {
        Some(exe)
    };
    let ppid = if event.ppid != 0 {
        event.ppid
    } else {
        proc_ppid(event.pid).unwrap_or(0)
    };
    let event_name = if event.kind == EVENT_KIND_EXIT {
        "exit"
    } else {
        "execve"
    };
    let argv_hash = if event.kind == EVENT_KIND_EXECVE {
        exe_value.as_deref().map(stable_hash_hex)
    } else {
        None
    };
    json!({
        "ts": rfc3339_now(),
        "run_id": config.run_id,
        "sample_id": config.sample_id,
        "pid": event.pid,
        "ppid": ppid,
        "tgid": event.tgid,
        "comm": bytes_to_string(event.comm_bytes()),
        "exe": exe_value,
        "argv_hash": argv_hash,
        "event": event_name,
        "container_id": config.container_id,
        "cgroup_id": cgroup_json(event.cgroup_id),
    })
}

pub fn render_network_event(event: &SensorEvent, config: &SensorConfig) -> Value {
    json!({
        "ts": rfc3339_now(),
        "run_id": config.run_id,
        "sample_id": config.sample_id,
        "source": "aya_connect",
        "flow_id": null,
        "pid": event.pid,
        "src_ip": null,
        "src_port": null,
        "dst_ip": dst_ip_string(event),
        "dst_port": event.dst_port,
        "proto": proto_name(event.proto),
        "retval": event.retval,
        "container_id": config.container_id,
        "cgroup_id": cgroup_json(event.cgroup_id),
    })
}

fn dst_ip_string(event: &SensorEvent) -> String {
    match event.dst_family {
        SENSOR_AF_INET => {
            let bytes = event.dst_ip_bytes();
            if bytes.len() == 4 {
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
            } else {
                String::new()
            }
        }
        SENSOR_AF_INET6 => {
            let bytes = event.dst_ip_bytes();
            if bytes.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Ipv6Addr::from(octets).to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "other",
    }
}

fn cgroup_json(cgroup_id: u64) -> Option<String> {
    if cgroup_id == 0 {
        None
    } else {
        Some(cgroup_id.to_string())
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn proc_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 2..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

fn proc_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn stable_hash_hex(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_from_unix(now.as_secs())
}

fn rfc3339_from_unix(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use snoop_common::SENSOR_COMM_MAX;

    fn test_config() -> SensorConfig {
        SensorConfig {
            run_id: "run-test".into(),
            sample_id: "sample-test".into(),
            files_log: PathBuf::from("/tmp/files.jsonl"),
            proc_log: PathBuf::from("/tmp/proc.jsonl"),
            network_log: Some(PathBuf::from("/tmp/network.jsonl")),
            canary_catalog: None,
            canary_mount: "/canary".into(),
            target_cgroup_id: Some(42),
            container_id: Some("container-test".into()),
            duration: Duration::from_millis(1),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("exfil-analyzer-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_bytes<const N: usize>(dest: &mut [u8; N], value: &str) -> u16 {
        let bytes = value.as_bytes();
        let len = bytes.len().min(N);
        dest[..len].copy_from_slice(&bytes[..len]);
        len as u16
    }

    fn base_event(kind: u32) -> SensorEvent {
        let mut event = SensorEvent::empty();
        event.kind = kind;
        event.pid = 1234;
        event.tgid = 1234;
        event.ppid = 1200;
        event.cgroup_id = 42;
        event.comm[..4].copy_from_slice(b"curl");
        event
    }

    #[test]
    fn canary_path_matcher_marks_catalog_and_mount_paths() {
        let dir = temp_dir("canary-match");
        let secret = dir.join("canary_rsa");
        fs::write(&secret, "fake").unwrap();
        fs::write(
            dir.join("canary.json"),
            format!(
                r#"{{"run_id":"r","generated_at":"2026-07-02T00:00:00Z","secrets":[{{"secret_id":"s","type":"canary_rsa","path":"{}","match_token":"tok"}}]}}"#,
                secret.display()
            ),
        )
        .unwrap();
        let matcher =
            CanaryPathMatcher::from_catalog_path(&dir.join("canary.json"), "/canary").unwrap();
        assert!(matcher.is_canary(secret.to_str().unwrap()));
        assert!(matcher.is_canary("/canary/canary_rsa"));
    }

    #[test]
    fn canary_path_matcher_rejects_unlisted_paths() {
        let matcher = CanaryPathMatcher {
            paths: vec!["/canary/canary_rsa".into()],
        };
        assert!(!matcher.is_canary("/etc/passwd"));
    }

    #[test]
    fn render_file_event_matches_schema_shape() {
        let mut event = base_event(EVENT_KIND_OPENAT);
        event.path_len = write_bytes(&mut event.path, "/canary/canary_rsa");
        let matcher = CanaryPathMatcher {
            paths: vec!["/canary/canary_rsa".into()],
        };
        let value = render_file_event(&event, &test_config(), &matcher);
        assert_eq!(value["run_id"], "run-test");
        assert_eq!(value["sample_id"], "sample-test");
        assert_eq!(value["pid"], 1234);
        assert_eq!(value["tgid"], 1234);
        assert_eq!(value["comm"], "curl");
        assert_eq!(value["path"], "/canary/canary_rsa");
        assert_eq!(value["is_canary"], true);
        assert_eq!(value["container_id"], "container-test");
        assert_eq!(value["cgroup_id"], "42");
        assert!(value["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn render_proc_event_matches_schema_shape() {
        let mut event = base_event(EVENT_KIND_EXECVE);
        event.exe_len = write_bytes(&mut event.exe, "/bin/wget");
        let value = render_proc_event(&event, &test_config());
        assert_eq!(value["run_id"], "run-test");
        assert_eq!(value["sample_id"], "sample-test");
        assert_eq!(value["pid"], 1234);
        assert_eq!(value["ppid"], 1200);
        assert_eq!(value["tgid"], 1234);
        assert_eq!(value["comm"], "curl");
        assert_eq!(value["exe"], "/bin/wget");
        assert_eq!(value["event"], "execve");
        assert!(value["argv_hash"].as_str().unwrap().len() == 16);
        assert_eq!(value["container_id"], "container-test");
        assert_eq!(value["cgroup_id"], "42");
    }

    #[test]
    fn render_network_event_matches_schema_shape_for_ipv4() {
        let mut event = base_event(EVENT_KIND_CONNECT);
        event.dst_family = SENSOR_AF_INET;
        event.dst_ip[..4].copy_from_slice(&[198, 51, 100, 10]);
        event.dst_port = 80;
        event.proto = PROTO_TCP;
        event.retval = -101;
        let value = render_network_event(&event, &test_config());
        assert_eq!(value["run_id"], "run-test");
        assert_eq!(value["sample_id"], "sample-test");
        assert_eq!(value["source"], "aya_connect");
        assert!(value["flow_id"].is_null());
        assert_eq!(value["pid"], 1234);
        assert!(value["src_ip"].is_null());
        assert!(value["src_port"].is_null());
        assert_eq!(value["dst_ip"], "198.51.100.10");
        assert_eq!(value["dst_port"], 80);
        assert_eq!(value["proto"], "tcp");
        assert_eq!(value["retval"], -101);
        assert_eq!(value["container_id"], "container-test");
        assert_eq!(value["cgroup_id"], "42");
    }

    #[test]
    fn render_network_event_matches_schema_shape_for_ipv6() {
        let mut event = base_event(EVENT_KIND_CONNECT);
        event.dst_family = SENSOR_AF_INET6;
        event.dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        event.dst_port = 443;
        event.proto = PROTO_UDP;
        let value = render_network_event(&event, &test_config());
        assert_eq!(value["dst_ip"], "2001:db8::1");
        assert_eq!(value["dst_port"], 443);
        assert_eq!(value["proto"], "udp");
    }

    #[test]
    fn event_scope_rejects_other_cgroup() {
        let mut event = SensorEvent::empty();
        event.cgroup_id = 7;
        assert!(event_in_scope(&event, None));
        assert!(event_in_scope(&event, Some(0)));
        assert!(event_in_scope(&event, Some(7)));
        assert!(!event_in_scope(&event, Some(42)));
    }

    #[test]
    fn comm_bytes_trim_nul() {
        let mut event = SensorEvent::empty();
        let mut comm = [0u8; SENSOR_COMM_MAX];
        comm[..3].copy_from_slice(b"sh\0");
        event.comm = comm;
        assert_eq!(bytes_to_string(event.comm_bytes()), "sh");
    }
}

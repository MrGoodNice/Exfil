#![no_std]

pub const OBSERVER_NAME: &str = "exfil-analyzer-rust-observer";
pub const SENSOR_PATH_MAX: usize = 256;
pub const SENSOR_COMM_MAX: usize = 16;
pub const EVENT_KIND_OPENAT: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;
pub const EVENT_KIND_EXIT: u32 = 3;
pub const EVENT_KIND_CONNECT: u32 = 4;
pub const SENSOR_AF_INET: u16 = 2;
pub const SENSOR_AF_INET6: u16 = 10;
pub const PROTO_OTHER: u8 = 0;
pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BringupEvent {
    pub pid: u32,
    pub tid: u32,
    pub counter: u64,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SensorEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub comm: [u8; SENSOR_COMM_MAX],
    pub path_len: u16,
    pub exe_len: u16,
    pub _pad: u32,
    pub retval: i64,
    pub fd: i32,
    pub dst_port: u16,
    pub dst_family: u16,
    pub proto: u8,
    pub _pad2: [u8; 3],
    pub dst_ip: [u8; 16],
    pub path: [u8; SENSOR_PATH_MAX],
    pub exe: [u8; SENSOR_PATH_MAX],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectArgs {
    pub fd: i32,
    pub dst_family: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
    pub dst_ip: [u8; 16],
}

impl ConnectArgs {
    #[inline]
    pub fn empty() -> Self {
        Self {
            fd: 0,
            dst_family: 0,
            dst_port: 0,
            proto: PROTO_OTHER,
            _pad: [0; 3],
            dst_ip: [0; 16],
        }
    }
}

impl Default for ConnectArgs {
    fn default() -> Self {
        Self::empty()
    }
}

impl SensorEvent {
    #[inline]
    pub fn empty() -> Self {
        Self {
            kind: 0,
            pid: 0,
            tgid: 0,
            ppid: 0,
            cgroup_id: 0,
            timestamp_ns: 0,
            comm: [0; SENSOR_COMM_MAX],
            path_len: 0,
            exe_len: 0,
            _pad: 0,
            retval: 0,
            fd: 0,
            dst_port: 0,
            dst_family: 0,
            proto: PROTO_OTHER,
            _pad2: [0; 3],
            dst_ip: [0; 16],
            path: [0; SENSOR_PATH_MAX],
            exe: [0; SENSOR_PATH_MAX],
        }
    }

    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        let len = (self.path_len as usize).min(SENSOR_PATH_MAX);
        trim_nul(&self.path[..len])
    }

    #[inline]
    pub fn exe_bytes(&self) -> &[u8] {
        let len = (self.exe_len as usize).min(SENSOR_PATH_MAX);
        trim_nul(&self.exe[..len])
    }

    #[inline]
    pub fn comm_bytes(&self) -> &[u8] {
        trim_nul(&self.comm)
    }

    #[inline]
    pub fn dst_ip_bytes(&self) -> &[u8] {
        match self.dst_family {
            SENSOR_AF_INET => &self.dst_ip[..4],
            SENSOR_AF_INET6 => &self.dst_ip[..16],
            _ => &[],
        }
    }
}

impl Default for SensorEvent {
    fn default() -> Self {
        Self::empty()
    }
}

#[inline]
fn trim_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(index) => &bytes[..index],
        None => bytes,
    }
}

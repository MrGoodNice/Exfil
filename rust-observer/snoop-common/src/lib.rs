#![no_std]

pub const OBSERVER_NAME: &str = "exfil-analyzer-rust-observer";
pub const SENSOR_PATH_MAX: usize = 256;
pub const SENSOR_COMM_MAX: usize = 16;
pub const EVENT_KIND_OPENAT: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;
pub const EVENT_KIND_EXIT: u32 = 3;

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
    pub path: [u8; SENSOR_PATH_MAX],
    pub exe: [u8; SENSOR_PATH_MAX],
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

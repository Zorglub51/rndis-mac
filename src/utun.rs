//! macOS utun: PF_SYSTEM control socket that gives us a layer-3 (IP-only)
//! virtual interface. Reads and writes are framed with a 4-byte big-endian
//! address family prefix (AF_INET = 2, AF_INET6 = 30) followed by the IP
//! packet.

use anyhow::{bail, Result};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const PF_SYSTEM: i32 = 32;
const AF_SYSTEM: u8 = 32;
const SYSPROTO_CONTROL: i32 = 2;
const AF_SYS_CONTROL: u16 = 2;
const SOCK_DGRAM: i32 = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME: i32 = 2;
const CTLIOCGINFO: libc::c_ulong = 0xC0644E03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C, packed(2))]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct Utun {
    fd: OwnedFd,
    pub name: String,
}

impl Utun {
    pub fn create() -> Result<Self> {
        unsafe {
            let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                bail!("socket(PF_SYSTEM) failed: {}", std::io::Error::last_os_error());
            }
            let owned = OwnedFd::from_raw_fd(fd);

            let mut info = CtlInfo { ctl_id: 0, ctl_name: [0u8; 96] };
            let name = UTUN_CONTROL_NAME.as_bytes();
            info.ctl_name[..name.len()].copy_from_slice(name);
            if libc::ioctl(owned.as_raw_fd(), CTLIOCGINFO, &mut info as *mut _) < 0 {
                bail!("CTLIOCGINFO: {}", std::io::Error::last_os_error());
            }

            let addr = SockaddrCtl {
                sc_len: mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: info.ctl_id,
                sc_unit: 0, // 0 = next available
                sc_reserved: [0; 5],
            };
            if libc::connect(
                owned.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<SockaddrCtl>() as u32,
            ) < 0
            {
                bail!("connect(utun): {}", std::io::Error::last_os_error());
            }

            // Get the assigned interface name.
            let mut buf = [0u8; 32];
            let mut len = buf.len() as libc::socklen_t;
            if libc::getsockopt(
                owned.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                buf.as_mut_ptr() as *mut _,
                &mut len,
            ) < 0
            {
                bail!("getsockopt(UTUN_OPT_IFNAME): {}", std::io::Error::last_os_error());
            }
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let name = std::str::from_utf8(&buf[..nul])?.to_string();

            Ok(Self { fd: owned, name })
        }
    }

    /// Read one IP packet (without the 4-byte AF prefix). Returns the AF + payload.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<(u32, usize)> {
        let n = unsafe {
            libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n < 0 {
            bail!("utun read: {}", std::io::Error::last_os_error());
        }
        if n < 4 {
            bail!("utun read too short: {n}");
        }
        let af = u32::from_be_bytes(buf[..4].try_into().unwrap());
        Ok((af, n as usize - 4))
    }

    /// Write an IP packet. `af` is AF_INET (2) or AF_INET6 (30).
    pub fn write_packet(&self, af: u32, payload: &[u8]) -> Result<()> {
        let mut iov = Vec::with_capacity(4 + payload.len());
        iov.extend_from_slice(&af.to_be_bytes());
        iov.extend_from_slice(payload);
        let n = unsafe {
            libc::write(self.fd.as_raw_fd(), iov.as_ptr() as *const _, iov.len())
        };
        if n < 0 {
            bail!("utun write: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 30;

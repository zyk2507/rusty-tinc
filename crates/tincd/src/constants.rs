use crate::*;

pub const DEFAULT_CONFDIR: &str = "/etc/tinc";
#[cfg(target_os = "linux")]
pub(crate) const DEFAULT_LINUX_TUN_DEVICE: &str = "/dev/net/tun";
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub(crate) const DEFAULT_BSD_TUN_DEVICE: &str = "/dev/tun";
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub(crate) const DEFAULT_BSD_TAP_DEVICE: &str = "/dev/tap";
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))
))]
pub(crate) const DEFAULT_BSD_TUN_DEVICE: &str = "/dev/tun0";
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))
))]
pub(crate) const DEFAULT_BSD_TAP_DEVICE: &str = "/dev/tap0";
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFNAMSIZ: usize = 16;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_TAP: libc::c_short = 0x0002;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_NO_PI: libc::c_short = 0x1000;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_ONE_QUEUE: libc::c_short = 0x2000;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_TUNSETIFF: libc::c_ulong = 0x400454ca;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_SIOCGIFINDEX: libc::c_ulong = 0x8933;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_ETH_P_ALL: u16 = 0x0003;
pub(crate) const LEGACY_REQ_KEY_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const SPTPS_REQ_KEY_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const TINC_TIMER_JITTER_US: usize = 131_072;
pub(crate) const MAX_SYSTEMD_LISTEN_FDS: usize = 8;

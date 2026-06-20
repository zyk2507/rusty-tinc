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
pub(crate) const LINUX_IFNAMSIZ: usize = libc::IFNAMSIZ;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_TUN: libc::c_short = libc::IFF_TUN as libc::c_short;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_TAP: libc::c_short = libc::IFF_TAP as libc::c_short;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_NO_PI: libc::c_short = libc::IFF_NO_PI as libc::c_short;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_IFF_ONE_QUEUE: libc::c_short = libc::IFF_ONE_QUEUE as libc::c_short;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_TUNSETIFF: libc::Ioctl = libc::TUNSETIFF;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_SIOCGIFINDEX: libc::Ioctl = libc::SIOCGIFINDEX as libc::Ioctl;
#[cfg(target_os = "linux")]
pub(crate) const LINUX_ETH_P_ALL: u16 = libc::ETH_P_ALL as u16;
pub(crate) const LEGACY_REQ_KEY_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const SPTPS_REQ_KEY_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const TINC_TIMER_JITTER_US: usize = 131_072;
pub(crate) const MAX_SYSTEMD_LISTEN_FDS: usize = 8;

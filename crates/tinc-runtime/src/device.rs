// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};

use tinc_core::route::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6};

pub const DEFAULT_PACKET_OFFSET: usize = 12;
#[cfg(not(feature = "jumbograms"))]
pub const MTU: usize = 1518;
#[cfg(feature = "jumbograms")]
pub const MTU: usize = 9018;
pub const MIN_MTU: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind {
    Dummy,
    Memory,
    Tun,
    Tap,
    FileDescriptor,
    RawSocket,
    Multicast,
    Uml,
    Vde,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    pub device: String,
    pub interface: Option<String>,
    pub description: String,
}

impl DeviceInfo {
    pub fn new(
        kind: DeviceKind,
        device: impl Into<String>,
        interface: Option<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            device: device.into(),
            interface,
            description: description.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VpnPacket {
    pub data: Vec<u8>,
    pub priority: i32,
}

impl VpnPacket {
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Self, DeviceError> {
        let data = data.into();

        if data.len() > MTU {
            return Err(DeviceError::PacketTooLarge {
                maximum: MTU,
                actual: data.len(),
            });
        }

        Ok(Self { data, priority: 0 })
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug)]
pub enum DeviceError {
    Io(io::Error),
    PacketTooLarge {
        maximum: usize,
        actual: usize,
    },
    PacketTooShort {
        expected_at_least: usize,
        actual: usize,
    },
    UnknownIpVersion(u8),
}

impl Clone for DeviceError {
    fn clone(&self) -> Self {
        match self {
            Self::Io(error) => Self::Io(io::Error::new(error.kind(), error.to_string())),
            Self::PacketTooLarge { maximum, actual } => Self::PacketTooLarge {
                maximum: *maximum,
                actual: *actual,
            },
            Self::PacketTooShort {
                expected_at_least,
                actual,
            } => Self::PacketTooShort {
                expected_at_least: *expected_at_least,
                actual: *actual,
            },
            Self::UnknownIpVersion(version) => Self::UnknownIpVersion(*version),
        }
    }
}

impl PartialEq for DeviceError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            (
                Self::PacketTooLarge {
                    maximum: left_maximum,
                    actual: left_actual,
                },
                Self::PacketTooLarge {
                    maximum: right_maximum,
                    actual: right_actual,
                },
            ) => left_maximum == right_maximum && left_actual == right_actual,
            (
                Self::PacketTooShort {
                    expected_at_least: left_expected,
                    actual: left_actual,
                },
                Self::PacketTooShort {
                    expected_at_least: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (Self::UnknownIpVersion(left), Self::UnknownIpVersion(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for DeviceError {}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::PacketTooLarge { maximum, actual } => {
                write!(f, "packet too large: {actual} > {maximum}")
            }
            Self::PacketTooShort {
                expected_at_least,
                actual,
            } => write!(
                f,
                "packet too short: expected at least {expected_at_least}, got {actual}"
            ),
            Self::UnknownIpVersion(version) => write!(f, "unknown IP version {version}"),
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DeviceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait Device {
    fn info(&self) -> &DeviceInfo;
    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError>;
    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError>;

    fn enable(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }

    fn disable(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DummyDevice {
    info: DeviceInfo,
    writes: Vec<VpnPacket>,
}

impl DummyDevice {
    pub fn new() -> Self {
        Self {
            info: DeviceInfo::new(
                DeviceKind::Dummy,
                "dummy",
                Some("dummy".to_owned()),
                "dummy device",
            ),
            writes: Vec::new(),
        }
    }

    pub fn writes(&self) -> &[VpnPacket] {
        &self.writes
    }
}

impl Default for DummyDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for DummyDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        Ok(None)
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        self.writes.push(packet.clone());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MemoryDevice {
    info: DeviceInfo,
    reads: VecDeque<VpnPacket>,
    writes: Vec<VpnPacket>,
}

impl MemoryDevice {
    pub fn new(reads: impl IntoIterator<Item = VpnPacket>) -> Self {
        Self {
            info: DeviceInfo::new(
                DeviceKind::Memory,
                "memory",
                Some("memory".to_owned()),
                "memory device",
            ),
            reads: reads.into_iter().collect(),
            writes: Vec::new(),
        }
    }

    pub fn push_read(&mut self, packet: VpnPacket) {
        self.reads.push_back(packet);
    }

    pub fn writes(&self) -> &[VpnPacket] {
        &self.writes
    }
}

impl Device for MemoryDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        Ok(self.reads.pop_front())
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        self.writes.push(packet.clone());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameMode {
    Tap,
    Tun,
    BsdTunIfHead,
    Fd,
    RawSocket,
}

pub fn decode_device_frame(mode: FrameMode, input: &[u8]) -> Result<VpnPacket, DeviceError> {
    let data = match mode {
        FrameMode::Tap | FrameMode::RawSocket => input.to_vec(),
        FrameMode::Tun => ethernet_frame_from_tun_pi(input)?,
        FrameMode::BsdTunIfHead => ethernet_frame_from_bsd_tun_ifhead(input)?,
        FrameMode::Fd => ethernet_frame_from_ip_payload(input)?,
    };

    VpnPacket::new(data)
}

pub fn encode_device_frame(mode: FrameMode, packet: &VpnPacket) -> Result<Vec<u8>, DeviceError> {
    match mode {
        FrameMode::Tap | FrameMode::RawSocket => Ok(packet.data.clone()),
        FrameMode::Tun => tun_pi_from_ethernet_frame(&packet.data),
        FrameMode::BsdTunIfHead => bsd_tun_ifhead_from_ethernet_frame(&packet.data),
        FrameMode::Fd => ip_payload_from_ethernet_frame(&packet.data),
    }
}

pub fn ethernet_frame_from_ip_payload(payload: &[u8]) -> Result<Vec<u8>, DeviceError> {
    let Some(first) = payload.first() else {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: 1,
            actual: 0,
        });
    };

    let ether_type = match first >> 4 {
        4 => ETH_P_IP,
        6 => ETH_P_IPV6,
        version => return Err(DeviceError::UnknownIpVersion(version)),
    };

    let mut frame = Vec::with_capacity(ETH_HLEN + payload.len());
    frame.resize(ETH_HLEN - 2, 0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn ethernet_frame_from_tun_pi(input: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if input.len() < 4 {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: 4,
            actual: input.len(),
        });
    }

    let mut frame = Vec::with_capacity(ETH_HLEN + input.len() - 4);
    frame.resize(ETH_HLEN - 4, 0);
    frame.extend_from_slice(input);
    Ok(frame)
}

pub fn tun_pi_from_ethernet_frame(frame: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if frame.len() < ETH_HLEN {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: ETH_HLEN,
            actual: frame.len(),
        });
    }

    Ok(frame[ETH_HLEN - 4..].to_vec())
}

pub fn ethernet_frame_from_bsd_tun_ifhead(input: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if input.len() < 5 {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: 5,
            actual: input.len(),
        });
    }

    let ether_type = match input[4] >> 4 {
        4 => ETH_P_IP,
        6 => ETH_P_IPV6,
        version => return Err(DeviceError::UnknownIpVersion(version)),
    };

    let mut frame = Vec::with_capacity(ETH_HLEN + input.len() - 4);
    frame.resize(ETH_HLEN - 2, 0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(&input[4..]);
    Ok(frame)
}

pub fn bsd_tun_ifhead_from_ethernet_frame(frame: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if frame.len() < ETH_HLEN {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: ETH_HLEN,
            actual: frame.len(),
        });
    }

    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let family: u32 = match ether_type {
        ETH_P_IP => bsd_tun_ifhead_af_inet(),
        ETH_P_IPV6 => bsd_tun_ifhead_af_inet6(),
        other => {
            return Err(DeviceError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown Ethernet protocol {other:#x} for BSD tun"),
            )));
        }
    };

    let mut output = Vec::with_capacity(frame.len() - 10);
    output.extend_from_slice(&family.to_be_bytes());
    output.extend_from_slice(&frame[ETH_HLEN..]);
    Ok(output)
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "macos"))]
fn bsd_tun_ifhead_af_inet() -> u32 {
    libc::AF_INET as u32
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "macos"))]
fn bsd_tun_ifhead_af_inet6() -> u32 {
    libc::AF_INET6 as u32
}

#[cfg(target_os = "openbsd")]
fn bsd_tun_ifhead_af_inet() -> u32 {
    2
}

#[cfg(target_os = "openbsd")]
fn bsd_tun_ifhead_af_inet6() -> u32 {
    24
}

#[cfg(target_os = "netbsd")]
fn bsd_tun_ifhead_af_inet() -> u32 {
    2
}

#[cfg(target_os = "netbsd")]
fn bsd_tun_ifhead_af_inet6() -> u32 {
    24
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
fn bsd_tun_ifhead_af_inet() -> u32 {
    2
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
fn bsd_tun_ifhead_af_inet6() -> u32 {
    10
}

pub fn ip_payload_from_ethernet_frame(frame: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if frame.len() < ETH_HLEN {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: ETH_HLEN,
            actual: frame.len(),
        });
    }

    Ok(frame[ETH_HLEN..].to_vec())
}

#[derive(Debug)]
pub struct FileDevice<T> {
    info: DeviceInfo,
    mode: FrameMode,
    inner: T,
}

impl<T> FileDevice<T> {
    pub fn new(
        inner: T,
        mode: FrameMode,
        device: impl Into<String>,
        interface: Option<String>,
    ) -> Self {
        let kind = match mode {
            FrameMode::Tap => DeviceKind::Tap,
            FrameMode::Tun | FrameMode::BsdTunIfHead => DeviceKind::Tun,
            FrameMode::Fd => DeviceKind::FileDescriptor,
            FrameMode::RawSocket => DeviceKind::RawSocket,
        };
        let description = match mode {
            FrameMode::Tap => "TAP device",
            FrameMode::Tun | FrameMode::BsdTunIfHead => "TUN device",
            FrameMode::Fd => "file descriptor device",
            FrameMode::RawSocket => "raw socket device",
        };

        Self {
            info: DeviceInfo::new(kind, device, interface, description),
            mode,
            inner,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Read + Write> Device for FileDevice<T> {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        let mut buffer = vec![0; MTU];
        let len = match self.inner.read(&mut buffer) {
            Ok(len) => len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(DeviceError::Io(error)),
        };

        if len == 0 {
            return Ok(None);
        }

        buffer.truncate(len);
        Ok(Some(decode_device_frame(self.mode, &buffer)?))
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        let frame = encode_device_frame(self.mode, packet)?;
        self.inner.write_all(&frame)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, SeekFrom};

    use super::*;

    fn ipv4_payload() -> Vec<u8> {
        let mut payload = vec![0; 20];
        payload[0] = 0x45;
        payload
    }

    fn ipv6_payload() -> Vec<u8> {
        let mut payload = vec![0; 40];
        payload[0] = 0x60;
        payload
    }

    fn tun_pi_ipv4_payload() -> Vec<u8> {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&ETH_P_IP.to_be_bytes());
        payload.extend_from_slice(&ipv4_payload());
        payload
    }

    fn bsd_tun_ifhead_ipv4_payload() -> Vec<u8> {
        let mut payload = 2_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&ipv4_payload());
        payload
    }

    fn ethernet_ipv4_frame() -> Vec<u8> {
        let mut frame = vec![0; ETH_HLEN];
        frame[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        frame.extend_from_slice(&ipv4_payload());
        frame
    }

    #[test]
    fn device_mtu_tracks_core_default_mtu_and_c_jumbograms_option() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(tinc_core::graph::DEFAULT_MTU, MTU);
        #[cfg(feature = "jumbograms")]
        assert_eq!(9018, MTU);
        #[cfg(not(feature = "jumbograms"))]
        assert_eq!(1518, MTU);

        assert!(VpnPacket::new(vec![0; MTU]).is_ok());
        assert_eq!(
            Err(DeviceError::PacketTooLarge {
                maximum: MTU,
                actual: MTU + 1
            }),
            VpnPacket::new(vec![0; MTU + 1])
        );
    }

    #[test]
    fn memory_device_queues_reads_and_records_writes() {
        tinc_test_support::assert_can_create_netns();
        let first = VpnPacket::new(ethernet_ipv4_frame()).unwrap();
        let second = VpnPacket::new(vec![1, 2, 3]).unwrap();
        let mut device = MemoryDevice::new([first.clone()]);

        assert_eq!(Some(first), device.read_packet().unwrap());
        assert_eq!(None, device.read_packet().unwrap());

        device.push_read(second.clone());
        assert_eq!(Some(second.clone()), device.read_packet().unwrap());
        device.write_packet(&second).unwrap();
        assert_eq!(&[second], device.writes());
    }

    #[test]
    fn dummy_device_discards_reads_and_records_writes() {
        tinc_test_support::assert_can_create_netns();
        let packet = VpnPacket::new(ethernet_ipv4_frame()).unwrap();
        let mut device = DummyDevice::new();

        assert_eq!(None, device.read_packet().unwrap());
        device.write_packet(&packet).unwrap();
        assert_eq!(&[packet], device.writes());
        assert_eq!(DeviceKind::Dummy, device.info().kind);
    }

    #[test]
    fn tun_mode_maps_linux_pi_header_to_ethernet_header_on_read() {
        tinc_test_support::assert_can_create_netns();
        let pi_payload = tun_pi_ipv4_payload();
        let packet = decode_device_frame(FrameMode::Tun, &pi_payload).unwrap();

        assert_eq!(ETH_HLEN + 20, packet.len());
        assert_eq!([0; ETH_HLEN - 4], packet.data[..ETH_HLEN - 4]);
        assert_eq!(
            ETH_P_IP,
            u16::from_be_bytes([packet.data[12], packet.data[13]])
        );
        assert_eq!(ipv4_payload(), packet.data[ETH_HLEN..]);
    }

    #[test]
    fn fd_mode_adds_ethernet_headers_to_raw_ip_on_read() {
        tinc_test_support::assert_can_create_netns();
        let packet = decode_device_frame(FrameMode::Fd, &ipv6_payload()).unwrap();
        assert_eq!(ETH_HLEN + 40, packet.len());
        assert_eq!(
            ETH_P_IPV6,
            u16::from_be_bytes([packet.data[12], packet.data[13]])
        );
    }

    #[test]
    fn tun_mode_writes_linux_pi_header_and_ip_payload() {
        tinc_test_support::assert_can_create_netns();
        let packet = VpnPacket::new(ethernet_ipv4_frame()).unwrap();
        let encoded = encode_device_frame(FrameMode::Tun, &packet).unwrap();
        assert_eq!(tun_pi_ipv4_payload(), encoded);
    }

    #[test]
    fn bsd_tun_ifhead_mode_matches_c_tunifhead_header_shape() {
        tinc_test_support::assert_can_create_netns();
        let input = bsd_tun_ifhead_ipv4_payload();
        let packet = decode_device_frame(FrameMode::BsdTunIfHead, &input).unwrap();

        assert_eq!(ETH_HLEN + 20, packet.len());
        assert_eq!([0; ETH_HLEN - 2], packet.data[..ETH_HLEN - 2]);
        assert_eq!(
            ETH_P_IP,
            u16::from_be_bytes([packet.data[12], packet.data[13]])
        );
        assert_eq!(ipv4_payload(), packet.data[ETH_HLEN..]);
        assert_eq!(
            input,
            encode_device_frame(FrameMode::BsdTunIfHead, &packet).unwrap()
        );

        let mut ipv6 = 24_u32.to_be_bytes().to_vec();
        ipv6.extend_from_slice(&ipv6_payload());
        let packet = decode_device_frame(FrameMode::BsdTunIfHead, &ipv6).unwrap();
        assert_eq!(
            ETH_P_IPV6,
            u16::from_be_bytes([packet.data[12], packet.data[13]])
        );
    }

    #[test]
    fn fd_mode_strips_ethernet_headers_on_write() {
        tinc_test_support::assert_can_create_netns();
        let packet = VpnPacket::new(ethernet_ipv4_frame()).unwrap();
        let encoded = encode_device_frame(FrameMode::Fd, &packet).unwrap();
        assert_eq!(ipv4_payload(), encoded);
    }

    #[test]
    fn tap_mode_preserves_full_ethernet_frames() {
        tinc_test_support::assert_can_create_netns();
        let frame = ethernet_ipv4_frame();
        let packet = decode_device_frame(FrameMode::Tap, &frame).unwrap();
        assert_eq!(frame, packet.data);
        assert_eq!(frame, encode_device_frame(FrameMode::Tap, &packet).unwrap());
    }

    #[test]
    fn raw_socket_mode_preserves_full_ethernet_frames() {
        tinc_test_support::assert_can_create_netns();
        let frame = ethernet_ipv4_frame();
        let packet = decode_device_frame(FrameMode::RawSocket, &frame).unwrap();
        assert_eq!(frame, packet.data);
        assert_eq!(
            frame,
            encode_device_frame(FrameMode::RawSocket, &packet).unwrap()
        );
    }

    #[test]
    fn frame_conversion_rejects_invalid_packets() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(DeviceError::PacketTooShort {
                expected_at_least: 4,
                actual: 1,
            }),
            decode_device_frame(FrameMode::Tun, &[0x70])
        );
        assert_eq!(
            Err(DeviceError::UnknownIpVersion(7)),
            decode_device_frame(FrameMode::Fd, &[0x70])
        );
        assert_eq!(
            Err(DeviceError::PacketTooShort {
                expected_at_least: ETH_HLEN,
                actual: 3,
            }),
            ip_payload_from_ethernet_frame(&[1, 2, 3])
        );
    }

    #[test]
    fn file_device_reads_and_writes_with_frame_conversion() {
        tinc_test_support::assert_can_create_netns();
        let mut input = Cursor::new(ipv4_payload());
        let mut device = FileDevice::new(&mut input, FrameMode::Fd, "fd/0", None);

        let packet = device.read_packet().unwrap().unwrap();
        assert_eq!(
            ETH_P_IP,
            u16::from_be_bytes([packet.data[12], packet.data[13]])
        );

        let mut output = Cursor::new(Vec::new());
        let mut device = FileDevice::new(&mut output, FrameMode::Fd, "fd/1", None);
        device.write_packet(&packet).unwrap();

        output.seek(SeekFrom::Start(0)).unwrap();
        let mut written = Vec::new();
        output.read_to_end(&mut written).unwrap();
        assert_eq!(ipv4_payload(), written);
    }
}

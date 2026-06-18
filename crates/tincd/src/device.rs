use crate::*;

#[derive(Debug)]
pub(crate) enum RuntimeDevice {
    Dummy(DummyDevice),
    Memory(MemoryDevice),
    File(FileDevice<File>),
    Multicast(MulticastDevice),
    #[cfg(target_os = "linux")]
    Uml(LinuxUmlDevice),
    #[cfg(all(unix, feature = "vde"))]
    Vde(VdeDevice),
}

impl RuntimeDevice {
    pub(crate) fn memory() -> Self {
        Self::Memory(MemoryDevice::new([]))
    }

    pub(crate) fn open(config: &RuntimeConfig) -> Result<Self, TincdError> {
        let device = &config.daemon.device;
        match &device.device_type {
            DeviceType::Dummy => Ok(Self::Dummy(DummyDevice::new())),
            DeviceType::System => {
                let mode = if config.engine.route.routing_mode == RoutingMode::Router {
                    FrameMode::Tun
                } else {
                    FrameMode::Tap
                };
                open_tun_tap_device(device, mode)
            }
            DeviceType::Tun => open_tun_tap_device(device, FrameMode::Tun),
            DeviceType::Tap => open_tun_tap_device(device, FrameMode::Tap),
            DeviceType::Fd => open_fd_device(device),
            DeviceType::RawSocket => open_raw_socket_device(device),
            DeviceType::Multicast => open_multicast_device(device),
            DeviceType::Uml => open_uml_device(device),
            DeviceType::Vde => open_vde_device(&config.name, device),
            other => Err(TincdError::RuntimeState(format!(
                "device type {other:?} is not supported yet"
            ))),
        }
    }

    pub(crate) fn writes(&self) -> &[VpnPacket] {
        match self {
            Self::Dummy(device) => device.writes(),
            Self::Memory(device) => device.writes(),
            Self::File(_) | Self::Multicast(_) => &[],
            #[cfg(target_os = "linux")]
            Self::Uml(_) => &[],
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(_) => &[],
        }
    }

    pub(crate) fn push_read(&mut self, packet: VpnPacket) -> Result<(), TincdError> {
        match self {
            Self::Memory(device) => {
                device.push_read(packet);
                Ok(())
            }
            Self::Dummy(_) | Self::File(_) | Self::Multicast(_) => Err(TincdError::RuntimeState(
                "cannot inject test packet into runtime device".to_owned(),
            )),
            #[cfg(target_os = "linux")]
            Self::Uml(_) => Err(TincdError::RuntimeState(
                "cannot inject test packet into runtime device".to_owned(),
            )),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(_) => Err(TincdError::RuntimeState(
                "cannot inject test packet into runtime device".to_owned(),
            )),
        }
    }
}

impl Device for RuntimeDevice {
    fn info(&self) -> &DeviceInfo {
        match self {
            Self::Dummy(device) => device.info(),
            Self::Memory(device) => device.info(),
            Self::File(device) => device.info(),
            Self::Multicast(device) => device.info(),
            #[cfg(target_os = "linux")]
            Self::Uml(device) => device.info(),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(device) => device.info(),
        }
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        match self {
            Self::Dummy(device) => device.read_packet(),
            Self::Memory(device) => device.read_packet(),
            Self::File(device) => device.read_packet(),
            Self::Multicast(device) => device.read_packet(),
            #[cfg(target_os = "linux")]
            Self::Uml(device) => device.read_packet(),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(device) => device.read_packet(),
        }
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        match self {
            Self::Dummy(device) => device.write_packet(packet),
            Self::Memory(device) => device.write_packet(packet),
            Self::File(device) => device.write_packet(packet),
            Self::Multicast(device) => device.write_packet(packet),
            #[cfg(target_os = "linux")]
            Self::Uml(device) => device.write_packet(packet),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(device) => device.write_packet(packet),
        }
    }

    fn enable(&mut self) -> Result<(), DeviceError> {
        match self {
            Self::Dummy(device) => device.enable(),
            Self::Memory(device) => device.enable(),
            Self::File(device) => device.enable(),
            Self::Multicast(device) => device.enable(),
            #[cfg(target_os = "linux")]
            Self::Uml(device) => device.enable(),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(device) => device.enable(),
        }
    }

    fn disable(&mut self) -> Result<(), DeviceError> {
        match self {
            Self::Dummy(device) => device.disable(),
            Self::Memory(device) => device.disable(),
            Self::File(device) => device.disable(),
            Self::Multicast(device) => device.disable(),
            #[cfg(target_os = "linux")]
            Self::Uml(device) => device.disable(),
            #[cfg(all(unix, feature = "vde"))]
            Self::Vde(device) => device.disable(),
        }
    }
}

pub(crate) fn open_fd_device(config: &DeviceConfig) -> Result<RuntimeDevice, TincdError> {
    let Some(device) = config.device.as_deref() else {
        return Err(TincdError::RuntimeState(
            "DeviceType = fd requires Device".to_owned(),
        ));
    };

    let file = open_fd_device_file(device)?;
    set_file_descriptor_flags(&file)?;
    Ok(RuntimeDevice::File(FileDevice::new(
        file,
        FrameMode::Fd,
        device.to_owned(),
        config.interface.clone(),
    )))
}

pub(crate) fn open_raw_socket_device(config: &DeviceConfig) -> Result<RuntimeDevice, TincdError> {
    open_platform_raw_socket_device(config)
}

#[derive(Debug)]
pub(crate) struct MulticastDevice {
    pub(crate) info: DeviceInfo,
    pub(crate) socket: UdpSocket,
    pub(crate) target: SocketAddr,
    pub(crate) ignore_src: [u8; 6],
}

impl MulticastDevice {
    pub(crate) fn new(
        socket: UdpSocket,
        target: SocketAddr,
        device: String,
        interface: Option<String>,
    ) -> Self {
        Self {
            info: DeviceInfo::new(DeviceKind::Multicast, device, interface, "multicast socket"),
            socket,
            target,
            ignore_src: [0; 6],
        }
    }
}

impl Device for MulticastDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        let mut buffer = vec![0; tinc_runtime::device::MTU];
        let len = match self.socket.recv(&mut buffer) {
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
        if buffer
            .get(6..12)
            .is_some_and(|source| source == self.ignore_src)
        {
            return Ok(None);
        }

        VpnPacket::new(buffer).map(Some)
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        let source = packet.data.get(6..12).ok_or(DeviceError::PacketTooShort {
            expected_at_least: 12,
            actual: packet.data.len(),
        })?;
        self.socket.send_to(&packet.data, self.target)?;
        self.ignore_src.copy_from_slice(source);
        Ok(())
    }
}

pub(crate) fn open_multicast_device(config: &DeviceConfig) -> Result<RuntimeDevice, TincdError> {
    open_platform_multicast_device(config)
}

#[cfg(unix)]
pub(crate) fn open_platform_multicast_device(
    config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    let device = config.device.clone().ok_or_else(|| {
        TincdError::RuntimeState("Device variable required for multicast socket".to_owned())
    })?;
    let multicast = parse_multicast_device(&device)?;
    let target = resolve_multicast_target(&multicast.host, &multicast.port)?;
    let socket = open_bound_udp_socket(&target)?;
    join_multicast_group(&socket, target, multicast.ttl)?;
    set_raw_descriptor_flags(socket.as_raw_fd())?;

    Ok(RuntimeDevice::Multicast(MulticastDevice::new(
        socket,
        target,
        device,
        config.interface.clone(),
    )))
}

#[cfg(not(unix))]
pub(crate) fn open_platform_multicast_device(
    _config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    Err(TincdError::RuntimeState(
        "multicast device is not supported on this platform yet".to_owned(),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MulticastDeviceConfig {
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) ttl: i32,
}

pub(crate) fn parse_multicast_device(device: &str) -> Result<MulticastDeviceConfig, TincdError> {
    let Some((host, rest)) = device.split_once(' ') else {
        return Err(TincdError::RuntimeState(
            "Port number required for multicast socket".to_owned(),
        ));
    };
    let (port, ttl) = match rest.split_once(' ') {
        Some((port, ttl)) => (port, c_atoi_prefix(ttl)),
        None => (rest, 1),
    };

    Ok(MulticastDeviceConfig {
        host: host.to_owned(),
        port: port.to_owned(),
        ttl,
    })
}

pub(crate) fn c_atoi_prefix(value: &str) -> i32 {
    let bytes = value.as_bytes();
    let mut index = 0;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }

    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };

    let mut value = 0i32;
    let mut saw_digit = false;
    while let Some(byte @ b'0'..=b'9') = bytes.get(index).copied() {
        saw_digit = true;
        value = value
            .saturating_mul(10)
            .saturating_add(i32::from(byte - b'0'));
        index += 1;
    }

    if !saw_digit {
        0
    } else if negative {
        value.saturating_neg()
    } else {
        value
    }
}

pub(crate) fn resolve_multicast_target(host: &str, port: &str) -> Result<SocketAddr, TincdError> {
    let address = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    address
        .to_socket_addrs()
        .map_err(|error| {
            TincdError::RuntimeState(format!(
                "could not resolve multicast device {host} {port}: {error}"
            ))
        })?
        .next()
        .ok_or_else(|| {
            TincdError::RuntimeState(format!("could not resolve multicast device {host} {port}"))
        })
}

#[cfg(unix)]
pub(crate) fn open_bound_udp_socket(target: &SocketAddr) -> Result<UdpSocket, TincdError> {
    let family = match target {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(TincdError::RuntimeState(format!(
            "creating multicast socket failed: {}",
            io::Error::last_os_error()
        )));
    }

    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }

    let (address, length) = socket_addr_to_raw(target);
    if unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_storage).cast(),
            length,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(TincdError::RuntimeState(format!(
            "can't bind to {} {}: {error}",
            target.ip(),
            target.port()
        )));
    }

    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

#[cfg(unix)]
pub(crate) fn socket_addr_to_raw(
    address: &SocketAddr,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match address {
        SocketAddr::V4(address) => {
            let raw = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(address) => {
            let raw = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: address.ip().octets(),
            };
            raw.sin6_scope_id = address.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

pub(crate) fn join_multicast_group(
    socket: &UdpSocket,
    target: SocketAddr,
    ttl: i32,
) -> Result<(), TincdError> {
    match target {
        SocketAddr::V4(address) => {
            socket
                .join_multicast_v4(address.ip(), &Ipv4Addr::UNSPECIFIED)
                .map_err(|error| {
                    TincdError::RuntimeState(format!(
                        "cannot join multicast group {} {}: {error}",
                        address.ip(),
                        address.port()
                    ))
                })?;
            let _ = socket.set_multicast_loop_v4(true);
            let _ = socket.set_multicast_ttl_v4(u32::try_from(ttl).unwrap_or(0));
        }
        SocketAddr::V6(address) => {
            socket
                .join_multicast_v6(address.ip(), address.scope_id())
                .map_err(|error| {
                    TincdError::RuntimeState(format!(
                        "cannot join multicast group {} {}: {error}",
                        address.ip(),
                        address.port()
                    ))
                })?;
            let _ = socket.set_multicast_loop_v6(true);
            set_ipv6_multicast_hops(socket, ttl);
        }
    }

    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_ipv6_multicast_hops(socket: &UdpSocket, ttl: i32) {
    let value = ttl as libc::c_int;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn set_ipv6_multicast_hops(_socket: &UdpSocket, _ttl: i32) {}

pub(crate) fn open_uml_device(config: &DeviceConfig) -> Result<RuntimeDevice, TincdError> {
    open_platform_uml_device(config)
}

pub(crate) fn open_vde_device(
    local_name: &str,
    config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    open_platform_vde_device(local_name, config)
}

#[cfg(all(unix, feature = "vde"))]
#[link(name = "vdeplug")]
unsafe extern "C" {
    fn vde_open(
        vde_switch: *const libc::c_char,
        descr: *const libc::c_char,
        open_args: *mut VdeOpenArgs,
    ) -> *mut VdeConnection;
    fn vde_close(conn: *mut VdeConnection) -> libc::c_int;
    fn vde_datafd(conn: *mut VdeConnection) -> libc::c_int;
    fn vde_recv(
        conn: *mut VdeConnection,
        buf: *mut libc::c_void,
        len: libc::size_t,
        flags: libc::c_int,
    ) -> libc::ssize_t;
    fn vde_send(
        conn: *mut VdeConnection,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

#[cfg(all(unix, feature = "vde"))]
#[repr(C)]
pub(crate) struct VdeOpenArgs {
    pub(crate) port: libc::c_int,
    pub(crate) group: *const libc::c_char,
    pub(crate) mode: libc::mode_t,
}

#[cfg(all(unix, feature = "vde"))]
pub(crate) enum VdeConnection {}

#[cfg(all(unix, feature = "vde"))]
#[derive(Debug)]
pub(crate) struct VdeDevice {
    pub(crate) info: DeviceInfo,
    pub(crate) conn: *mut VdeConnection,
}

#[cfg(all(unix, feature = "vde"))]
impl VdeDevice {
    pub(crate) fn open(
        device: String,
        interface: Option<String>,
        port: i32,
        group: Option<&str>,
        local_name: &str,
    ) -> Result<Self, TincdError> {
        let device_c = CString::new(device.as_str()).map_err(|_| {
            TincdError::RuntimeState(format!("VDE socket path contains NUL: {device:?}"))
        })?;
        let local_name_c = CString::new(local_name).map_err(|_| {
            TincdError::RuntimeState(format!("VDE description contains NUL: {local_name:?}"))
        })?;
        let group_c = group
            .map(CString::new)
            .transpose()
            .map_err(|_| TincdError::RuntimeState("VDEGroup contains NUL".to_owned()))?;
        let mut args = VdeOpenArgs {
            port: port as libc::c_int,
            group: group_c
                .as_ref()
                .map_or(std::ptr::null(), |group| group.as_ptr()),
            mode: 0o700,
        };
        let conn = unsafe { vde_open(device_c.as_ptr(), local_name_c.as_ptr(), &mut args) };

        if conn.is_null() {
            return Err(TincdError::RuntimeState(format!(
                "Could not open VDE socket {device}"
            )));
        }

        let fd = unsafe { vde_datafd(conn) };
        if fd >= 0 {
            set_raw_descriptor_flags(fd)?;
        }

        Ok(Self {
            info: DeviceInfo::new(DeviceKind::Vde, device, interface, "VDE socket"),
            conn,
        })
    }
}

#[cfg(all(unix, feature = "vde"))]
impl Device for VdeDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        let mut buffer = vec![0; tinc_runtime::device::MTU];
        let len = unsafe {
            vde_recv(
                self.conn,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };

        if len <= 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }

        let len = len as usize;
        if len == 1 || len < ETH_HLEN {
            return Ok(None);
        }

        buffer.truncate(len);
        VpnPacket::new(buffer).map(Some)
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        let written = unsafe {
            vde_send(
                self.conn,
                packet.data.as_ptr().cast::<libc::c_void>(),
                packet.data.len(),
                0,
            )
        };

        if written < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(());
            }
            return Err(DeviceError::Io(error));
        }

        Ok(())
    }
}

#[cfg(all(unix, feature = "vde"))]
impl Drop for VdeDevice {
    fn drop(&mut self) {
        if !self.conn.is_null() {
            unsafe {
                vde_close(self.conn);
            }
            self.conn = std::ptr::null_mut();
        }
    }
}

#[cfg(all(unix, feature = "vde"))]
pub(crate) fn open_platform_vde_device(
    local_name: &str,
    config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    let device = config
        .device
        .clone()
        .unwrap_or_else(default_vde_socket_path);
    Ok(RuntimeDevice::Vde(VdeDevice::open(
        device,
        config.interface.clone(),
        config.vde_port,
        config.vde_group.as_deref(),
        local_name,
    )?))
}

#[cfg(not(all(unix, feature = "vde")))]
pub(crate) fn open_platform_vde_device(
    _local_name: &str,
    _config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    Err(TincdError::RuntimeState(
        "VDE socket device support is not enabled in this build".to_owned(),
    ))
}

#[cfg(all(unix, feature = "vde"))]
pub(crate) fn default_vde_socket_path() -> String {
    "/run/vde.ctl".to_owned()
}

#[cfg(target_os = "linux")]
pub(crate) fn open_platform_uml_device(config: &DeviceConfig) -> Result<RuntimeDevice, TincdError> {
    let device = config
        .device
        .clone()
        .unwrap_or_else(default_linux_uml_socket_path);
    Ok(RuntimeDevice::Uml(LinuxUmlDevice::open(
        device,
        config.interface.clone(),
    )?))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn open_platform_uml_device(
    _config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    Err(TincdError::RuntimeState(
        "UML network socket device is not supported on this platform yet".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn default_linux_uml_socket_path() -> String {
    "/run/tinc.umlsocket".to_owned()
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct LinuxUmlDevice {
    pub(crate) info: DeviceInfo,
    pub(crate) listen: Option<std::os::unix::net::UnixListener>,
    pub(crate) request: Option<std::os::unix::net::UnixStream>,
    pub(crate) data: std::os::unix::net::UnixDatagram,
    pub(crate) write: std::os::unix::net::UnixDatagram,
    pub(crate) data_addr: libc::sockaddr_un,
    pub(crate) state: LinuxUmlDeviceState,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxUmlDeviceState {
    Listen,
    Request,
    Connected,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LinuxUmlRequest {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) request_type: u32,
    pub(crate) sock: libc::sockaddr_un,
}

#[cfg(target_os = "linux")]
impl LinuxUmlDevice {
    pub(crate) fn open(device: String, interface: Option<String>) -> Result<Self, TincdError> {
        let _ = fs::remove_file(&device);
        let write = std::os::unix::net::UnixDatagram::unbound().map_err(|error| {
            TincdError::RuntimeState(format!("Could not open write UML network socket: {error}"))
        })?;
        set_raw_descriptor_flags(write.as_raw_fd())?;

        let data = std::os::unix::net::UnixDatagram::unbound().map_err(|error| {
            TincdError::RuntimeState(format!("Could not open data UML network socket: {error}"))
        })?;
        set_raw_descriptor_flags(data.as_raw_fd())?;

        let data_addr = linux_uml_abstract_data_addr()?;
        bind_unix_datagram_raw(data.as_raw_fd(), &data_addr).map_err(|error| {
            TincdError::RuntimeState(format!("Could not bind data UML network socket: {error}"))
        })?;

        let listener = std::os::unix::net::UnixListener::bind(&device).map_err(|error| {
            TincdError::RuntimeState(format!(
                "Could not bind UML network socket to {device}: {error}"
            ))
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            TincdError::RuntimeState(format!(
                "Could not set UML network socket non-blocking mode: {error}"
            ))
        })?;
        set_raw_descriptor_flags(listener.as_raw_fd())?;

        Ok(Self {
            info: DeviceInfo::new(DeviceKind::Uml, device, interface, "UML network socket"),
            listen: Some(listener),
            request: None,
            data,
            write,
            data_addr,
            state: LinuxUmlDeviceState::Listen,
        })
    }

    pub(crate) fn accept_request(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        let Some(listener) = &self.listen else {
            return Ok(None);
        };
        let (stream, _) = match listener.accept() {
            Ok(stream) => stream,
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

        stream.set_nonblocking(true)?;
        set_raw_descriptor_flags(stream.as_raw_fd()).map_err(runtime_state_to_device_io)?;
        self.listen = None;
        self.request = Some(stream);
        self.state = LinuxUmlDeviceState::Request;
        Ok(None)
    }

    pub(crate) fn handle_request(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        let Some(stream) = &mut self.request else {
            return Ok(None);
        };
        let mut request = LinuxUmlRequest {
            magic: 0,
            version: 0,
            request_type: 0,
            sock: unsafe { std::mem::zeroed() },
        };
        let request_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut request as *mut LinuxUmlRequest).cast::<u8>(),
                std::mem::size_of::<LinuxUmlRequest>(),
            )
        };

        match stream.read_exact(request_bytes) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(DeviceError::Io(error)),
        }

        if request.magic != 0xfeedface || request.version != 3 || request.request_type != 0 {
            return Err(DeviceError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unknown UML request magic {:x}, version {}, request type {}",
                    request.magic, request.version, request.request_type
                ),
            )));
        }

        connect_unix_datagram_raw(self.write.as_raw_fd(), &request.sock)?;
        let response_bytes = unsafe {
            std::slice::from_raw_parts(
                (&self.data_addr as *const libc::sockaddr_un).cast::<u8>(),
                std::mem::size_of::<libc::sockaddr_un>(),
            )
        };
        stream.write_all(response_bytes)?;
        self.state = LinuxUmlDeviceState::Connected;
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
impl Device for LinuxUmlDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn read_packet(&mut self) -> Result<Option<VpnPacket>, DeviceError> {
        match self.state {
            LinuxUmlDeviceState::Listen => self.accept_request(),
            LinuxUmlDeviceState::Request => self.handle_request(),
            LinuxUmlDeviceState::Connected => {
                let mut buffer = vec![0; tinc_runtime::device::MTU];
                let len = match self.data.recv(&mut buffer) {
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
                VpnPacket::new(buffer).map(Some)
            }
        }
    }

    fn write_packet(&mut self, packet: &VpnPacket) -> Result<(), DeviceError> {
        if self.state != LinuxUmlDeviceState::Connected {
            return Ok(());
        }

        match self.write.send(&packet.data) {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(DeviceError::Io(error)),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxUmlDevice {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.info.device);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_uml_abstract_data_addr() -> Result<libc::sockaddr_un, TincdError> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    address.sun_path[0] = 0;
    let pid = std::process::id() as i32;
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_micros() as i32;
    let name = [pid.to_ne_bytes(), micros.to_ne_bytes()].concat();

    if name.len() + 1 > address.sun_path.len() {
        return Err(TincdError::RuntimeState(
            "UML abstract socket name is too long".to_owned(),
        ));
    }

    for (index, byte) in name.iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }

    Ok(address)
}

#[cfg(target_os = "linux")]
pub(crate) fn bind_unix_datagram_raw(fd: RawFd, address: &libc::sockaddr_un) -> io::Result<()> {
    if unsafe {
        libc::bind(
            fd,
            (address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn connect_unix_datagram_raw(fd: RawFd, address: &libc::sockaddr_un) -> io::Result<()> {
    if unsafe {
        libc::connect(
            fd,
            (address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn runtime_state_to_device_io(error: TincdError) -> DeviceError {
    DeviceError::Io(io::Error::other(error.to_string()))
}

#[cfg(target_os = "linux")]
pub(crate) fn open_platform_raw_socket_device(
    config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    let interface = config
        .interface
        .clone()
        .unwrap_or_else(|| "eth0".to_owned());
    let device = config.device.clone().unwrap_or_else(|| interface.clone());
    let fd = unsafe {
        libc::socket(
            libc::PF_PACKET,
            libc::SOCK_RAW,
            LINUX_ETH_P_ALL.to_be() as libc::c_int,
        )
    };

    if fd < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not open raw_socket: {}",
            io::Error::last_os_error()
        )));
    }

    let mut request = linux_ifindex_ifreq(&interface)?;
    if unsafe { libc::ioctl(fd, LINUX_SIOCGIFINDEX, &mut request) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(TincdError::RuntimeState(format!(
            "can't find interface {interface}: {error}"
        )));
    }

    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as libc::c_ushort;
    address.sll_protocol = LINUX_ETH_P_ALL.to_be();
    address.sll_ifindex = request.ifindex;

    if unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(TincdError::RuntimeState(format!(
            "could not bind {device} to {interface}: {error}"
        )));
    }

    let file = unsafe { File::from_raw_fd(fd) };
    set_file_descriptor_flags(&file)?;
    Ok(RuntimeDevice::File(FileDevice::new(
        file,
        FrameMode::RawSocket,
        device,
        Some(interface),
    )))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn open_platform_raw_socket_device(
    _config: &DeviceConfig,
) -> Result<RuntimeDevice, TincdError> {
    Err(TincdError::RuntimeState(
        "raw socket device is not supported on this platform yet".to_owned(),
    ))
}

#[cfg(unix)]
pub(crate) fn open_fd_device_file(device: &str) -> Result<File, TincdError> {
    if let Ok(fd) = device.parse::<i32>() {
        if fd < 0 {
            return Err(TincdError::RuntimeState(format!(
                "invalid negative fd device {fd}"
            )));
        }

        return Ok(unsafe { File::from_raw_fd(fd) });
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map_err(|error| {
            TincdError::RuntimeState(format!("could not open fd device {device}: {error}"))
        })
}

#[cfg(not(unix))]
pub(crate) fn open_fd_device_file(device: &str) -> Result<File, TincdError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map_err(|error| {
            TincdError::RuntimeState(format!("could not open fd device {device}: {error}"))
        })
}

#[cfg(unix)]
pub(crate) fn set_file_descriptor_flags(file: &File) -> Result<(), TincdError> {
    set_raw_descriptor_flags(file.as_raw_fd())
}

#[cfg(unix)]
pub(crate) fn set_raw_descriptor_flags(fd: i32) -> Result<(), TincdError> {
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not get device status flags: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, status | libc::O_NONBLOCK) } < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not set device non-blocking mode: {}",
            io::Error::last_os_error()
        )));
    }

    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not get device fd flags: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not set device close-on-exec flag: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_file_descriptor_flags(_file: &File) -> Result<(), TincdError> {
    Ok(())
}

pub(crate) fn open_tun_tap_device(
    config: &DeviceConfig,
    mode: FrameMode,
) -> Result<RuntimeDevice, TincdError> {
    open_platform_tun_tap_device(config, mode)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_platform_tun_tap_device(
    config: &DeviceConfig,
    mode: FrameMode,
) -> Result<RuntimeDevice, TincdError> {
    let device = config.device.as_deref().unwrap_or(DEFAULT_LINUX_TUN_DEVICE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map_err(|error| {
            TincdError::RuntimeState(format!(
                "could not open Linux tun/tap device {device}: {error}"
            ))
        })?;
    set_file_descriptor_flags(&file)?;

    let flags = linux_tun_tap_flags(mode, config.iff_one_queue)?;
    let mut request = linux_ifreq(config.interface.as_deref(), flags)?;
    if unsafe { libc::ioctl(file.as_raw_fd(), LINUX_TUNSETIFF, &mut request) } < 0 {
        return Err(TincdError::RuntimeState(format!(
            "could not configure Linux tun/tap device {device}: {}",
            io::Error::last_os_error()
        )));
    }

    let interface = linux_ifreq_name(&request).or_else(|| config.interface.clone());
    Ok(RuntimeDevice::File(FileDevice::new(
        file,
        mode,
        device.to_owned(),
        interface,
    )))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_tun_tap_flags(
    mode: FrameMode,
    iff_one_queue: bool,
) -> Result<libc::c_short, TincdError> {
    let mut flags = match mode {
        FrameMode::Tun => LINUX_IFF_TUN,
        FrameMode::Tap => LINUX_IFF_TAP | LINUX_IFF_NO_PI,
        FrameMode::BsdTunIfHead | FrameMode::Fd | FrameMode::RawSocket => {
            return Err(TincdError::RuntimeState(
                "fd frame mode is not a tun/tap device".to_owned(),
            ));
        }
    };
    if iff_one_queue {
        flags |= LINUX_IFF_ONE_QUEUE;
    }
    Ok(flags)
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub(crate) fn open_platform_tun_tap_device(
    config: &DeviceConfig,
    mode: FrameMode,
) -> Result<RuntimeDevice, TincdError> {
    let device = config
        .device
        .clone()
        .unwrap_or_else(|| default_bsd_tun_tap_device(mode).to_owned());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device)
        .map_err(|error| {
            TincdError::RuntimeState(format!(
                "could not open BSD tun/tap device {device}: {error}"
            ))
        })?;
    set_file_descriptor_flags(&file)?;

    let interface = config
        .interface
        .clone()
        .or_else(|| bsd_tun_tap_interface_name(&device));
    let mode = match mode {
        FrameMode::Tap => FrameMode::Tap,
        FrameMode::Tun => FrameMode::BsdTunIfHead,
        FrameMode::BsdTunIfHead => FrameMode::BsdTunIfHead,
        FrameMode::Fd | FrameMode::RawSocket => {
            return Err(TincdError::RuntimeState(
                "fd frame mode is not a tun/tap device".to_owned(),
            ));
        }
    };

    Ok(RuntimeDevice::File(FileDevice::new(
        file, mode, device, interface,
    )))
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub(crate) fn default_bsd_tun_tap_device(mode: FrameMode) -> &'static str {
    match mode {
        FrameMode::Tap => DEFAULT_BSD_TAP_DEVICE,
        _ => DEFAULT_BSD_TUN_DEVICE,
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub(crate) fn bsd_tun_tap_interface_name(device: &str) -> Option<String> {
    Path::new(device)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub(crate) fn open_platform_tun_tap_device(
    _config: &DeviceConfig,
    _mode: FrameMode,
) -> Result<RuntimeDevice, TincdError> {
    Err(TincdError::RuntimeState(
        "tun/tap devices are not supported on this platform yet".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct LinuxIfreq {
    pub(crate) name: [libc::c_char; LINUX_IFNAMSIZ],
    pub(crate) flags: libc::c_short,
    pub(crate) padding: [u8; 22],
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct LinuxIfIndexIfreq {
    pub(crate) name: [libc::c_char; LINUX_IFNAMSIZ],
    pub(crate) ifindex: libc::c_int,
    pub(crate) padding: [u8; 20],
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ifreq(
    interface: Option<&str>,
    flags: libc::c_short,
) -> Result<LinuxIfreq, TincdError> {
    let mut request = LinuxIfreq {
        name: [0; LINUX_IFNAMSIZ],
        flags,
        padding: [0; 22],
    };

    if let Some(interface) = interface {
        let bytes = interface.as_bytes();
        if bytes.len() >= LINUX_IFNAMSIZ {
            return Err(TincdError::RuntimeState(format!(
                "interface name {interface} is too long"
            )));
        }
        for (index, byte) in bytes.iter().enumerate() {
            request.name[index] = *byte as libc::c_char;
        }
    }

    Ok(request)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ifindex_ifreq(interface: &str) -> Result<LinuxIfIndexIfreq, TincdError> {
    let mut request = LinuxIfIndexIfreq {
        name: [0; LINUX_IFNAMSIZ],
        ifindex: 0,
        padding: [0; 20],
    };
    let bytes = interface.as_bytes();

    if bytes.len() >= LINUX_IFNAMSIZ {
        return Err(TincdError::RuntimeState(format!(
            "interface name {interface} is too long"
        )));
    }

    for (index, byte) in bytes.iter().enumerate() {
        request.name[index] = *byte as libc::c_char;
    }

    Ok(request)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ifreq_name(request: &LinuxIfreq) -> Option<String> {
    let len = request
        .name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(LINUX_IFNAMSIZ);
    if len == 0 {
        return None;
    }

    let bytes = request.name[..len]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

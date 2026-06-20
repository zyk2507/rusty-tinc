use crate::*;

pub fn bind_runtime_listeners(
    config: &RuntimeConfig,
) -> Result<Vec<RuntimeListenSocket>, TincdError> {
    #[cfg(unix)]
    if let Some(sockets) = bind_runtime_listeners_from_systemd_env(config)? {
        return Ok(sockets);
    }

    let mut sockets: Vec<RuntimeListenSocket> = Vec::new();
    let mut dynamic_port = None;
    let mut last_error = None;

    for listen in config.daemon.effective_listen_addresses() {
        let targets = resolve_listen_targets(&listen, config.daemon.address_family, dynamic_port)?;

        for mut target in targets {
            if target.port() == 0
                && let Some(port) = dynamic_port
            {
                target.set_port(port);
            }

            if sockets.iter().any(|socket| socket.address == target) {
                continue;
            }

            match bind_runtime_listener(
                target,
                listen.bind_to,
                config.daemon.bind_to_interface.as_deref(),
                config.daemon.udp_rcvbuf,
                config.daemon.udp_sndbuf,
                config.daemon.fwmark,
                runtime_udp_pmtu_discovery_enabled(config),
            ) {
                Ok(socket) => {
                    if dynamic_port.is_none() && listen.port == "0" {
                        dynamic_port = Some(socket.address.port());
                    }
                    sockets.push(socket);
                }
                Err(error) => last_error = Some(error),
            }
        }
    }

    if sockets.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            TincdError::ListenIo("unable to create any listening socket".to_owned())
        }));
    }

    Ok(sockets)
}

#[cfg(unix)]
pub(crate) fn bind_runtime_listeners_from_systemd_env(
    config: &RuntimeConfig,
) -> Result<Option<Vec<RuntimeListenSocket>>, TincdError> {
    let Some(listen_fds) = systemd_listen_fds_env() else {
        return Ok(None);
    };

    unset_systemd_activation_env();
    let sockets = bind_runtime_listeners_from_systemd_fds(config, listen_fds, 3)?;
    Ok(Some(sockets))
}

#[cfg(unix)]
pub(crate) fn bind_runtime_listeners_from_systemd_fds(
    config: &RuntimeConfig,
    listen_fds: usize,
    first_fd: RawFd,
) -> Result<Vec<RuntimeListenSocket>, TincdError> {
    if listen_fds > MAX_SYSTEMD_LISTEN_FDS {
        return Err(TincdError::ListenIo(
            "Too many listening sockets".to_owned(),
        ));
    }

    let mut sockets = Vec::new();
    for index in 0..listen_fds {
        let fd = first_fd + index as RawFd;
        let tcp = take_systemd_tcp_listener(fd)?;
        let address = tcp.local_addr().map_err(listen_io)?;
        let udp = bind_runtime_udp_socket(
            address,
            config.daemon.bind_to_interface.as_deref(),
            config.daemon.udp_rcvbuf,
            config.daemon.udp_sndbuf,
            config.daemon.fwmark,
            runtime_udp_pmtu_discovery_enabled(config),
        )?;

        tcp.set_nonblocking(true).map_err(listen_io)?;
        udp.set_nonblocking(true).map_err(listen_io)?;

        sockets.push(RuntimeListenSocket {
            tcp,
            udp,
            address,
            bind_to: false,
            priority: Cell::new(0),
        });
    }

    if sockets.is_empty() {
        return Err(TincdError::ListenIo(
            "unable to create any listening socket".to_owned(),
        ));
    }

    Ok(sockets)
}

#[cfg(unix)]
pub(crate) fn take_systemd_tcp_listener(fd: RawFd) -> Result<TcpListener, TincdError> {
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(TincdError::ListenIo(format!(
            "Could not get address of listen fd {fd}: {}",
            io::Error::last_os_error()
        )));
    }

    set_raw_fd_cloexec(fd).map_err(listen_io)?;
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

pub(crate) fn bind_runtime_listener(
    address: SocketAddr,
    bind_to: bool,
    bind_to_interface: Option<&str>,
    udp_rcvbuf: i32,
    udp_sndbuf: i32,
    fwmark: i32,
    pmtu_discovery: bool,
) -> Result<RuntimeListenSocket, TincdError> {
    let tcp = bind_runtime_tcp_listener(address, bind_to_interface, fwmark)?;
    let address = tcp.local_addr().map_err(listen_io)?;
    let udp = bind_runtime_udp_socket(
        address,
        bind_to_interface,
        udp_rcvbuf,
        udp_sndbuf,
        fwmark,
        pmtu_discovery,
    )?;

    tcp.set_nonblocking(true).map_err(listen_io)?;
    udp.set_nonblocking(true).map_err(listen_io)?;

    Ok(RuntimeListenSocket {
        tcp,
        udp,
        address,
        bind_to,
        priority: Cell::new(0),
    })
}

#[cfg(unix)]
pub(crate) fn bind_runtime_tcp_listener(
    address: SocketAddr,
    bind_to_interface: Option<&str>,
    fwmark: i32,
) -> Result<TcpListener, TincdError> {
    let fd = create_runtime_socket(address, libc::SOCK_STREAM, libc::IPPROTO_TCP)?;
    if let Err(error) = configure_runtime_tcp_listener_fd(fd, address, bind_to_interface, fwmark) {
        unsafe {
            libc::close(fd);
        }
        return Err(listen_io(error));
    }
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

#[cfg(not(unix))]
pub(crate) fn bind_runtime_tcp_listener(
    address: SocketAddr,
    _bind_to_interface: Option<&str>,
    _fwmark: i32,
) -> Result<TcpListener, TincdError> {
    TcpListener::bind(address).map_err(listen_io)
}

#[cfg(unix)]
pub(crate) fn configure_runtime_tcp_listener_fd(
    fd: i32,
    address: SocketAddr,
    bind_to_interface: Option<&str>,
    fwmark: i32,
) -> io::Result<()> {
    set_raw_fd_cloexec(fd)?;
    set_socket_reuseaddr(fd);
    set_socket_ipv6_v6only(fd, address);
    set_socket_fwmark(fd, fwmark);
    if let Some(interface) = bind_to_interface {
        bind_socket_to_interface(fd, interface)?;
    }
    bind_raw_socket(fd, address)?;
    if unsafe { libc::listen(fd, 3) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn bind_runtime_udp_socket(
    address: SocketAddr,
    bind_to_interface: Option<&str>,
    udp_rcvbuf: i32,
    udp_sndbuf: i32,
    fwmark: i32,
    pmtu_discovery: bool,
) -> Result<UdpSocket, TincdError> {
    let fd = create_runtime_socket(address, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    if let Err(error) = configure_runtime_udp_socket_fd(
        fd,
        address,
        bind_to_interface,
        udp_rcvbuf,
        udp_sndbuf,
        fwmark,
        pmtu_discovery,
    ) {
        unsafe {
            libc::close(fd);
        }
        return Err(listen_io(error));
    }
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

#[cfg(not(unix))]
pub(crate) fn bind_runtime_udp_socket(
    address: SocketAddr,
    _bind_to_interface: Option<&str>,
    _udp_rcvbuf: i32,
    _udp_sndbuf: i32,
    _fwmark: i32,
    _pmtu_discovery: bool,
) -> Result<UdpSocket, TincdError> {
    UdpSocket::bind(address).map_err(listen_io)
}

#[cfg(unix)]
pub(crate) fn configure_runtime_udp_socket_fd(
    fd: i32,
    address: SocketAddr,
    bind_to_interface: Option<&str>,
    udp_rcvbuf: i32,
    udp_sndbuf: i32,
    fwmark: i32,
    pmtu_discovery: bool,
) -> io::Result<()> {
    set_raw_fd_cloexec(fd)?;
    set_socket_reuseaddr(fd);
    set_socket_broadcast(fd);
    set_udp_socket_buffer_fd(fd, libc::SO_RCVBUF, udp_rcvbuf);
    set_udp_socket_buffer_fd(fd, libc::SO_SNDBUF, udp_sndbuf);
    set_socket_ipv6_v6only(fd, address);
    set_udp_socket_pmtu_discovery(fd, address, pmtu_discovery);
    set_socket_fwmark(fd, fwmark);
    if let Some(interface) = bind_to_interface {
        bind_socket_to_interface(fd, interface)?;
    }
    bind_raw_socket(fd, address)
}

pub(crate) fn runtime_udp_pmtu_discovery_enabled(config: &RuntimeConfig) -> bool {
    runtime_meta_options(
        config.state.experimental,
        config.daemon.indirect_data,
        config.daemon.tcp_only,
        config.daemon.pmtu_discovery,
        config.daemon.clamp_mss,
        None,
    ) & OPTION_PMTU_DISCOVERY
        != 0
}

#[cfg(unix)]
pub(crate) fn create_runtime_socket(
    address: SocketAddr,
    socket_type: libc::c_int,
    protocol: libc::c_int,
) -> Result<i32, TincdError> {
    let family = match address {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(family, socket_type, protocol) };
    if fd < 0 {
        return Err(listen_io(io::Error::last_os_error()));
    }
    Ok(fd)
}

#[cfg(unix)]
pub(crate) fn bind_raw_socket(fd: i32, address: SocketAddr) -> io::Result<()> {
    let (raw_address, raw_length) = socket_addr_to_raw(&address);
    if unsafe {
        libc::bind(
            fd,
            (&raw_address as *const libc::sockaddr_storage).cast(),
            raw_length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_socket_reuseaddr(fd: i32) {
    let option: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
    }
}

#[cfg(unix)]
pub(crate) fn set_socket_broadcast(fd: i32) {
    let option: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
    }
}

#[cfg(unix)]
pub(crate) fn set_socket_ipv6_v6only(fd: i32, address: SocketAddr) {
    if !address.is_ipv6() {
        return;
    }
    let option: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
    }
}

#[cfg(unix)]
pub(crate) fn set_udp_socket_buffer_fd(fd: i32, option: libc::c_int, size: i32) {
    if size == 0 {
        return;
    }

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&size as *const i32).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn set_udp_socket_pmtu_discovery(fd: i32, address: SocketAddr, enabled: bool) {
    if !enabled {
        return;
    }

    match address {
        SocketAddr::V4(_) => {
            let option: libc::c_int = libc::IP_PMTUDISC_DO;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    (&option as *const libc::c_int).cast(),
                    std::mem::size_of_val(&option) as libc::socklen_t,
                );
            }
        }
        SocketAddr::V6(_) => {
            let option: libc::c_int = libc::IPV6_PMTUDISC_DO;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    (&option as *const libc::c_int).cast(),
                    std::mem::size_of_val(&option) as libc::socklen_t,
                );
            }
        }
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub(crate) fn set_udp_socket_pmtu_discovery(_fd: i32, _address: SocketAddr, _enabled: bool) {}

pub(crate) fn is_message_too_long(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_fwmark(fd: i32, fwmark: i32) {
    if fwmark == 0 {
        return;
    }

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&fwmark as *const i32).cast(),
            std::mem::size_of_val(&fwmark) as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_socket_fwmark(_fd: i32, _fwmark: i32) {}

#[cfg(unix)]
pub(crate) fn set_udp_socket_priority(
    socket: &RuntimeListenSocket,
    remote: SocketAddr,
    priority: i32,
) {
    if socket.priority.get() == priority {
        return;
    }

    socket.priority.set(priority);
    set_udp_socket_priority_fd(socket.udp.as_raw_fd(), remote, priority);
}

#[cfg(not(unix))]
pub(crate) fn set_udp_socket_priority(
    socket: &RuntimeListenSocket,
    _remote: SocketAddr,
    priority: i32,
) {
    if socket.priority.get() == priority {
        return;
    }

    socket.priority.set(priority);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn set_udp_socket_priority_fd(fd: i32, remote: SocketAddr, priority: i32) {
    let (level, option) = match remote {
        SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TOS),
        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
    };

    unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&priority as *const i32).cast(),
            std::mem::size_of_val(&priority) as libc::socklen_t,
        );
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub(crate) fn set_udp_socket_priority_fd(_fd: i32, _remote: SocketAddr, _priority: i32) {}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const IPTOS_LOWDELAY: libc::c_int = libc::IPTOS_LOWDELAY as libc::c_int;

#[cfg(unix)]
pub(crate) fn configure_tcp_stream(stream: &TcpStream, fwmark: i32) -> io::Result<()> {
    configure_tcp_fd(stream.as_raw_fd(), fwmark)
}

#[cfg(not(unix))]
pub(crate) fn configure_tcp_stream(stream: &TcpStream, _fwmark: i32) -> io::Result<()> {
    stream.set_nonblocking(true)
}

#[cfg(unix)]
pub(crate) fn configure_tcp_fd(fd: i32, fwmark: i32) -> io::Result<()> {
    set_raw_fd_nonblocking(fd, true)?;
    set_tcp_nodelay(fd);
    set_tcp_lowdelay(fd);
    set_socket_fwmark(fd, fwmark);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_tcp_nodelay(fd: i32) {
    let option: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn set_tcp_lowdelay(fd: i32) {
    let option: libc::c_int = IPTOS_LOWDELAY;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            (&option as *const libc::c_int).cast(),
            std::mem::size_of_val(&option) as libc::socklen_t,
        );
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub(crate) fn set_tcp_lowdelay(_fd: i32) {}

#[cfg(target_os = "linux")]
pub(crate) fn bind_socket_to_interface(fd: i32, interface: &str) -> io::Result<()> {
    let mut request = LinuxIfreq {
        name: [0; LINUX_IFNAMSIZ],
        flags: 0,
        padding: [0; 22],
    };
    let bytes = interface.as_bytes();
    if bytes.len() >= LINUX_IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {interface} is too long"),
        ));
    }
    for (index, byte) in bytes.iter().enumerate() {
        request.name[index] = *byte as libc::c_char;
    }

    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            (&request as *const LinuxIfreq).cast(),
            std::mem::size_of_val(&request) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn bind_socket_to_interface(_fd: i32, _interface: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn connect_tcp_stream(
    address: SocketAddr,
    fwmark: i32,
    bind_to_interface: Option<&str>,
    bind_address: Option<SocketAddr>,
) -> io::Result<(TcpStream, bool)> {
    let family = match address {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    if let Err(error) =
        configure_outgoing_tcp_fd(fd, address, fwmark, bind_to_interface, bind_address)
    {
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }

    let (raw_address, raw_length) = socket_addr_to_raw(&address);
    let connect_result = unsafe {
        libc::connect(
            fd,
            (&raw_address as *const libc::sockaddr_storage).cast(),
            raw_length,
        )
    };

    if connect_result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        return Ok((unsafe { TcpStream::from_raw_fd(fd) }, true));
    }

    Ok((unsafe { TcpStream::from_raw_fd(fd) }, false))
}

#[cfg(not(unix))]
pub(crate) fn connect_tcp_stream(
    address: SocketAddr,
    _fwmark: i32,
    _bind_to_interface: Option<&str>,
    _bind_address: Option<SocketAddr>,
) -> io::Result<(TcpStream, bool)> {
    TcpStream::connect(address).map(|stream| (stream, false))
}

#[cfg(unix)]
pub(crate) fn configure_outgoing_tcp_fd(
    fd: i32,
    address: SocketAddr,
    fwmark: i32,
    bind_to_interface: Option<&str>,
    bind_address: Option<SocketAddr>,
) -> io::Result<()> {
    configure_tcp_fd(fd, fwmark)?;
    set_raw_fd_cloexec(fd)?;
    set_socket_ipv6_v6only(fd, address);
    if let Some(interface) = bind_to_interface {
        bind_socket_to_interface(fd, interface)?;
    }
    if let Some(bind_address) = bind_address {
        let _ = bind_raw_socket(fd, bind_address);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_raw_fd_nonblocking(fd: i32, nonblocking: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_raw_fd_cloexec(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn resolve_listen_targets(
    listen: &ListenAddress,
    family: ListenAddressFamily,
    dynamic_port: Option<u16>,
) -> Result<Vec<SocketAddr>, TincdError> {
    let port = if listen.port == "0" {
        dynamic_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| listen.port.clone())
    } else {
        listen.port.clone()
    };

    let mut targets = match &listen.address {
        Some(address) => resolve_named_listen_targets(address, &port, family)?,
        None => resolve_wildcard_listen_targets(&port, family)?,
    };

    targets.sort();
    targets.dedup();

    if targets.is_empty() {
        return Err(TincdError::InvalidListenAddress(format_listen_address(
            listen,
        )));
    }

    Ok(targets)
}

pub(crate) fn resolve_named_listen_targets(
    address: &str,
    service: &str,
    family: ListenAddressFamily,
) -> Result<Vec<SocketAddr>, TincdError> {
    let port = service.parse::<u16>().ok();

    if let Ok(ip) = address.parse::<IpAddr>() {
        return if let Some(port) = port {
            Ok(if address_family_matches(ip, family) {
                vec![SocketAddr::new(ip, port)]
            } else {
                Vec::new()
            })
        } else {
            resolve_service_listen_targets(Some(address), service, family)
        };
    }

    if let Some(port) = port {
        (address, port)
            .to_socket_addrs()
            .map_err(listen_io)
            .map(|addresses| {
                addresses
                    .filter(|address| address_family_matches(address.ip(), family))
                    .collect()
            })
    } else {
        resolve_service_listen_targets(Some(address), service, family)
    }
}

pub(crate) fn resolve_wildcard_listen_targets(
    service: &str,
    family: ListenAddressFamily,
) -> Result<Vec<SocketAddr>, TincdError> {
    if let Ok(port) = service.parse::<u16>() {
        return Ok(match family {
            ListenAddressFamily::Any => vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            ],
            ListenAddressFamily::Ipv4 => {
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)]
            }
            ListenAddressFamily::Ipv6 => {
                vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)]
            }
        });
    }

    resolve_service_listen_targets(None, service, family)
}

#[cfg(unix)]
pub(crate) fn resolve_service_listen_targets(
    address: Option<&str>,
    service: &str,
    family: ListenAddressFamily,
) -> Result<Vec<SocketAddr>, TincdError> {
    let address = address
        .map(CString::new)
        .transpose()
        .map_err(|_| TincdError::InvalidListenAddress(service.to_owned()))?;
    let service =
        CString::new(service).map_err(|_| TincdError::InvalidListenAddress(service.to_owned()))?;
    let mut hints = unsafe { std::mem::zeroed::<libc::addrinfo>() };
    hints.ai_family = libc_listen_address_family(family);
    hints.ai_socktype = libc::SOCK_STREAM;
    if address.is_none() {
        hints.ai_flags = libc::AI_PASSIVE;
    }

    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    let error = unsafe {
        libc::getaddrinfo(
            address
                .as_ref()
                .map(|address| address.as_ptr())
                .unwrap_or(std::ptr::null()),
            service.as_ptr(),
            &hints,
            &mut result as *mut *mut libc::addrinfo,
        )
    };

    if error != 0 || result.is_null() {
        return Err(listen_io(io::Error::other(format!(
            "getaddrinfo failed for service {}",
            service.to_string_lossy()
        ))));
    }

    let mut addresses = Vec::new();
    let mut current = result;
    while !current.is_null() {
        if let Some(address) = unsafe { socket_addr_from_raw((*current).ai_addr) }
            && address_family_matches(address.ip(), family)
        {
            addresses.push(address);
        }
        current = unsafe { (*current).ai_next };
    }

    unsafe {
        libc::freeaddrinfo(result);
    }

    Ok(addresses)
}

#[cfg(not(unix))]
pub(crate) fn resolve_service_listen_targets(
    _address: Option<&str>,
    service: &str,
    _family: ListenAddressFamily,
) -> Result<Vec<SocketAddr>, TincdError> {
    Err(TincdError::InvalidListenAddress(service.to_owned()))
}

#[cfg(unix)]
pub(crate) fn libc_listen_address_family(family: ListenAddressFamily) -> libc::c_int {
    match family {
        ListenAddressFamily::Any => libc::AF_UNSPEC,
        ListenAddressFamily::Ipv4 => libc::AF_INET,
        ListenAddressFamily::Ipv6 => libc::AF_INET6,
    }
}

#[cfg(unix)]
unsafe fn socket_addr_from_raw(address: *const libc::sockaddr) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }

    match unsafe { (*address).sa_family as libc::c_int } {
        libc::AF_INET => {
            let address = unsafe { *(address.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            let port = u16::from_be(address.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let address = unsafe { *(address.cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            let port = u16::from_be(address.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

pub(crate) fn address_family_matches(address: IpAddr, family: ListenAddressFamily) -> bool {
    matches!(
        (address, family),
        (_, ListenAddressFamily::Any)
            | (IpAddr::V4(_), ListenAddressFamily::Ipv4)
            | (IpAddr::V6(_), ListenAddressFamily::Ipv6)
    )
}

pub(crate) fn is_local_connection(peer: SocketAddr) -> bool {
    peer.ip().is_loopback()
}

pub(crate) fn format_listen_address(listen: &ListenAddress) -> String {
    match &listen.address {
        Some(address) => format!("{address} {}", listen.port),
        None => format!("* {}", listen.port),
    }
}

#[cfg(unix)]
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeSignalAction {
    Terminate(libc::c_int),
    Reload(libc::c_int),
    Retry(libc::c_int),
}

#[cfg(unix)]
pub(crate) struct RuntimeSignalHandlers {
    pub(crate) read_fd: i32,
    pub(crate) write_fd: i32,
    pub(crate) old_handlers: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
impl RuntimeSignalHandlers {
    pub(crate) fn install() -> Result<Self, TincdError> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(TincdError::RuntimeState(format!(
                "System call `pipe` failed: {}",
                io::Error::last_os_error()
            )));
        }

        if let Err(error) = set_raw_fd_nonblocking(fds[0], true)
            .and_then(|()| set_raw_fd_nonblocking(fds[1], true))
            .and_then(|()| set_raw_fd_cloexec(fds[0]))
            .and_then(|()| set_raw_fd_cloexec(fds[1]))
        {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(TincdError::RuntimeState(format!(
                "System call `fcntl` failed: {error}"
            )));
        }

        SIGNAL_WRITE_FD.store(fds[1], Ordering::SeqCst);

        let mut handlers = Self {
            read_fd: fds[0],
            write_fd: fds[1],
            old_handlers: Vec::new(),
        };

        for signal in [
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGQUIT,
            libc::SIGINT,
            libc::SIGALRM,
        ] {
            if let Err(error) = handlers.install_one(signal) {
                SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
                return Err(error);
            }
        }

        Ok(handlers)
    }

    pub(crate) fn install_one(&mut self, signal: libc::c_int) -> Result<(), TincdError> {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        let mut old_action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = runtime_signal_handler as *const () as usize;
        action.sa_flags = 0;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }

        if unsafe { libc::sigaction(signal, &action, &mut old_action) } != 0 {
            return Err(TincdError::RuntimeState(format!(
                "System call `sigaction` failed: {}",
                io::Error::last_os_error()
            )));
        }

        self.old_handlers.push((signal, old_action));
        Ok(())
    }

    pub(crate) fn drain_actions(&self) -> Result<Vec<RuntimeSignalAction>, TincdError> {
        let mut actions = Vec::new();
        let mut buffer = [0u8; 64];

        loop {
            let read = unsafe {
                libc::read(
                    self.read_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read > 0 {
                actions.extend(runtime_signal_actions_from_bytes(&buffer[..read as usize]));
                continue;
            }

            if read == 0 {
                return Ok(actions);
            }

            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(actions);
            }

            return Err(TincdError::RuntimeState(format!(
                "System call `read` failed: {error}"
            )));
        }
    }

    pub(crate) fn read_fd(&self) -> RawFd {
        self.read_fd
    }
}

#[cfg(unix)]
impl Drop for RuntimeSignalHandlers {
    fn drop(&mut self) {
        for (signal, old_action) in self.old_handlers.iter().rev() {
            unsafe {
                libc::sigaction(*signal, old_action, std::ptr::null_mut());
            }
        }
        SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(unix)]
extern "C" fn runtime_signal_handler(signum: libc::c_int) {
    let fd = SIGNAL_WRITE_FD.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }

    let signal = [signum as u8];
    unsafe {
        libc::write(fd, signal.as_ptr().cast::<libc::c_void>(), signal.len());
    }
}

#[cfg(unix)]
pub(crate) fn runtime_signal_action(signal: libc::c_int) -> Option<RuntimeSignalAction> {
    match signal {
        libc::SIGTERM | libc::SIGQUIT | libc::SIGINT => {
            Some(RuntimeSignalAction::Terminate(signal))
        }
        libc::SIGHUP => Some(RuntimeSignalAction::Reload(signal)),
        libc::SIGALRM => Some(RuntimeSignalAction::Retry(signal)),
        _ => None,
    }
}

#[cfg(unix)]
pub(crate) fn runtime_signal_actions_from_bytes(bytes: &[u8]) -> Vec<RuntimeSignalAction> {
    bytes
        .iter()
        .filter_map(|signal| runtime_signal_action(i32::from(*signal)))
        .collect()
}

#[cfg(unix)]
pub(crate) fn runtime_signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGTERM => "SIGTERM",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGINT => "SIGINT",
        libc::SIGALRM => "SIGALRM",
        _ => "signal",
    }
}

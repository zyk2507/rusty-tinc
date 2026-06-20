use crate::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpnpProtocol {
    Tcp,
    Udp,
}

impl UpnpProtocol {
    const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpnpPortMapping {
    pub(crate) local_addr: SocketAddr,
    pub(crate) external_port: u16,
    pub(crate) internal_port: u16,
    pub(crate) protocol: UpnpProtocol,
    pub(crate) description: String,
    pub(crate) lease_duration_secs: u32,
}

pub(crate) fn initialize_upnp_like_tinc(runtime: &mut RuntimeDaemonState, config: &RuntimeConfig) {
    if !config.daemon.upnp.is_enabled() {
        return;
    }

    let mappings = upnp_port_mappings_like_tinc(runtime, config);

    if mappings.is_empty() {
        runtime.record_log_with_priority(0, LOG_WARNING, "[upnp] No listening sockets to map");
        return;
    }

    let discover_wait = Duration::from_secs(config.daemon.upnp.discover_wait.max(0) as u64);
    let refresh_period = Duration::from_secs(config.daemon.upnp.refresh_period.max(0) as u64);
    let (logger, receiver) = upnp_log_channel();

    if let Err(error) = spawn_upnp_refresh_thread(mappings, discover_wait, refresh_period, logger) {
        runtime.record_log_with_priority(
            0,
            LOG_ERR,
            format!("Unable to start UPnP-IGD client thread: {error}"),
        );
    } else {
        runtime.upnp_log_receiver = Some(receiver);
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeUpnpLogReceiver {
    pub(crate) receiver: mpsc::Receiver<RuntimeLogEntry>,
    #[cfg(unix)]
    wake: Option<std::os::unix::net::UnixDatagram>,
}

impl RuntimeUpnpLogReceiver {
    #[cfg(not(unix))]
    fn new(receiver: mpsc::Receiver<RuntimeLogEntry>) -> Self {
        Self { receiver }
    }

    #[cfg(unix)]
    fn new(
        receiver: mpsc::Receiver<RuntimeLogEntry>,
        wake: Option<std::os::unix::net::UnixDatagram>,
    ) -> Self {
        Self { receiver, wake }
    }

    #[cfg(unix)]
    pub(crate) fn poll_fd(&self) -> Option<RawFd> {
        self.wake.as_ref().map(AsRawFd::as_raw_fd)
    }

    #[cfg(not(unix))]
    pub(crate) fn drain_wake(&self) {}

    #[cfg(unix)]
    pub(crate) fn drain_wake(&self) {
        let Some(wake) = &self.wake else {
            return;
        };
        let mut buffer = [0u8; 64];
        loop {
            match wake.recv(&mut buffer) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn upnp_log_channel() -> (UpnpLogger, RuntimeUpnpLogReceiver) {
    let (sender, receiver) = mpsc::channel();
    let logger: UpnpLogger = Box::new(move |level, priority, message| {
        let _ = sender.send(RuntimeLogEntry {
            level,
            priority,
            message,
        });
    });
    (logger, RuntimeUpnpLogReceiver::new(receiver))
}

#[cfg(unix)]
pub(crate) fn upnp_log_channel() -> (UpnpLogger, RuntimeUpnpLogReceiver) {
    let (sender, receiver) = mpsc::channel();
    let wake = std::os::unix::net::UnixDatagram::pair()
        .and_then(|(read, write)| {
            read.set_nonblocking(true)?;
            write.set_nonblocking(true)?;
            Ok((read, write))
        })
        .ok();
    let wake_sender = wake.as_ref().and_then(|(_, write)| write.try_clone().ok());
    let wake_receiver = wake.map(|(read, _)| read);
    let logger: UpnpLogger = Box::new(move |level, priority, message| {
        let _ = sender.send(RuntimeLogEntry {
            level,
            priority,
            message,
        });
        if let Some(wake) = &wake_sender {
            let _ = wake.send(&[1]);
        }
    });
    (logger, RuntimeUpnpLogReceiver::new(receiver, wake_receiver))
}

pub(crate) fn upnp_port_mappings_like_tinc(
    runtime: &RuntimeDaemonState,
    config: &RuntimeConfig,
) -> Vec<UpnpPortMapping> {
    let mut mappings = Vec::new();
    let lease_duration_secs = config.daemon.upnp.refresh_period.max(0).saturating_mul(2) as u32;
    let description = runtime_ident_name(runtime.netname.as_deref());

    for socket in runtime.listen_sockets() {
        if config.daemon.upnp.maps_tcp()
            && let Ok(local_addr) = socket.tcp.local_addr()
        {
            mappings.push(UpnpPortMapping {
                local_addr,
                external_port: local_addr.port(),
                internal_port: local_addr.port(),
                protocol: UpnpProtocol::Tcp,
                description: description.clone(),
                lease_duration_secs,
            });
        }

        if config.daemon.upnp.maps_udp()
            && let Ok(local_addr) = socket.udp.local_addr()
        {
            mappings.push(UpnpPortMapping {
                local_addr,
                external_port: local_addr.port(),
                internal_port: local_addr.port(),
                protocol: UpnpProtocol::Udp,
                description: description.clone(),
                lease_duration_secs,
            });
        }
    }

    mappings
}

pub(crate) fn runtime_ident_name(netname: Option<&str>) -> String {
    netname
        .map(|netname| format!("tinc.{netname}"))
        .unwrap_or_else(|| "tinc".to_owned())
}

pub(crate) type UpnpLogger = Box<dyn FnMut(i32, i32, String) + Send + 'static>;
pub(crate) type SharedUpnpLogger = std::sync::Arc<std::sync::Mutex<UpnpLogger>>;

pub(crate) fn spawn_upnp_refresh_thread(
    mappings: Vec<UpnpPortMapping>,
    discover_wait: Duration,
    refresh_period: Duration,
    logger: UpnpLogger,
) -> io::Result<()> {
    thread::Builder::new()
        .name("tinc-upnp".to_owned())
        .spawn(move || {
            let logger = std::sync::Arc::new(std::sync::Mutex::new(logger));

            loop {
                let start = Instant::now();
                upnp_refresh_once(&mappings, discover_wait, logger.clone());
                let elapsed = start.elapsed();
                if refresh_period > elapsed {
                    thread::sleep(refresh_period - elapsed);
                }
            }
        })
        .map(|_| ())
}

pub(crate) fn upnp_refresh_once(
    mappings: &[UpnpPortMapping],
    discover_wait: Duration,
    logger: SharedUpnpLogger,
) {
    upnp_log(&logger, 3, LOG_INFO, "[upnp] Discovering IGD devices");

    match discover_upnp_gateway(discover_wait) {
        Ok(gateway) => {
            upnp_log(
                &logger,
                3,
                LOG_INFO,
                format!(
                    "[upnp] IGD found: {} (local address: {})",
                    gateway,
                    gateway_local_addr(&gateway)
                        .map(|address| address.ip().to_string())
                        .unwrap_or_else(|_| "unknown".to_owned())
                ),
            );

            for mapping in mappings {
                match upnp_add_mapping(&gateway, mapping) {
                    Ok(()) => upnp_log(
                        &logger,
                        3,
                        LOG_INFO,
                        format!(
                            "[upnp] Successfully set port mapping ({}:{} {} for {} seconds)",
                            mapping.local_addr.ip(),
                            mapping.external_port,
                            mapping.protocol.name(),
                            mapping.lease_duration_secs
                        ),
                    ),
                    Err(error) => upnp_log(
                        &logger,
                        3,
                        LOG_ERR,
                        format!(
                            "[upnp] Failed to set port mapping ({}:{} {} for {} seconds): {error}",
                            mapping.local_addr.ip(),
                            mapping.external_port,
                            mapping.protocol.name(),
                            mapping.lease_duration_secs
                        ),
                    ),
                }
            }
        }
        Err(error) => upnp_log(
            &logger,
            3,
            LOG_WARNING,
            format!("[upnp] Unable to find IGD devices: {error}"),
        ),
    }
}

pub(crate) fn upnp_log(
    logger: &SharedUpnpLogger,
    level: i32,
    priority: i32,
    message: impl Into<String>,
) {
    if let Ok(mut logger) = logger.lock() {
        logger(level, priority, message.into());
    }
}

pub(crate) fn discover_upnp_gateway(timeout: Duration) -> io::Result<igd_next::Gateway> {
    igd_next::search_gateway(igd_next::SearchOptions {
        timeout: Some(timeout),
        single_search_timeout: Some(timeout),
        ..Default::default()
    })
    .map_err(io::Error::other)
}

pub(crate) fn upnp_add_mapping(
    gateway: &igd_next::Gateway,
    mapping: &UpnpPortMapping,
) -> io::Result<()> {
    gateway
        .add_port(
            match mapping.protocol {
                UpnpProtocol::Tcp => igd_next::PortMappingProtocol::TCP,
                UpnpProtocol::Udp => igd_next::PortMappingProtocol::UDP,
            },
            mapping.external_port,
            mapping.local_addr,
            mapping.lease_duration_secs,
            &mapping.description,
        )
        .map_err(io::Error::other)
}

pub(crate) fn gateway_local_addr(gateway: &igd_next::Gateway) -> io::Result<SocketAddr> {
    let bind = match gateway.addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(gateway.addr)?;
    socket.local_addr()
}

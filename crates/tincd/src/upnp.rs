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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpnpService {
    pub(crate) description_url: Url,
    pub(crate) control_url: Url,
    pub(crate) service_type: String,
    pub(crate) lan_address: IpAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpnpHttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: String,
}

pub(crate) const UPNP_DISCOVERY_TARGETS: &[&str] = &[
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
pub(crate) const UPNP_MULTICAST_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
pub(crate) const UPNP_HTTP_TIMEOUT: Duration = Duration::from_secs(3);

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
    let (sender, receiver) = mpsc::channel();
    let logger: UpnpLogger = Box::new(move |level, priority, message| {
        let _ = sender.send(RuntimeLogEntry {
            level,
            priority,
            message,
        });
    });

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

    match discover_upnp_service(discover_wait) {
        Ok(service) => {
            upnp_log(
                &logger,
                3,
                LOG_INFO,
                format!(
                    "[upnp] IGD found: {} (local address: {}, service type: {})",
                    service.control_url, service.lan_address, service.service_type
                ),
            );

            for mapping in mappings {
                match upnp_add_mapping(&service, mapping) {
                    Ok(()) => upnp_log(
                        &logger,
                        3,
                        LOG_INFO,
                        format!(
                            "[upnp] Successfully set port mapping ({}:{} {} for {} seconds)",
                            service.lan_address,
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
                            service.lan_address,
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

pub(crate) fn discover_upnp_service(timeout: Duration) -> io::Result<UpnpService> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.set_multicast_loop_v4(false).ok();
    socket.set_multicast_ttl_v4(2).ok();

    for target in UPNP_DISCOVERY_TARGETS {
        let request = upnp_discovery_request(target);
        socket.send_to(request.as_bytes(), UPNP_MULTICAST_ADDR)?;
    }

    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 2048];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no IGD discovery response",
            ));
        }
        socket.set_read_timeout(Some(remaining))?;

        let (len, source) = match socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no IGD discovery response",
                ));
            }
            Err(error) => return Err(error),
        };
        let response = String::from_utf8_lossy(&buffer[..len]);
        let headers = parse_http_headers(&response);
        let Some(location) = headers.get("location") else {
            continue;
        };
        let Ok(description_url) = Url::parse(location) else {
            continue;
        };
        let lan_address = local_addr_for_remote(source)?.ip();

        match fetch_upnp_service_description(description_url, lan_address, timeout) {
            Ok(service) => return Ok(service),
            Err(_) => continue,
        }
    }
}

pub(crate) fn upnp_discovery_request(target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {target}\r\n\
         \r\n"
    )
}

pub(crate) fn fetch_upnp_service_description(
    description_url: Url,
    lan_address: IpAddr,
    timeout: Duration,
) -> io::Result<UpnpService> {
    let response = http_get(&description_url, timeout)?;
    if response.status / 100 != 2 {
        return Err(io::Error::other(format!(
            "description request returned HTTP {}",
            response.status
        )));
    }

    parse_upnp_service_description(&description_url, lan_address, &response.body)
}

pub(crate) fn parse_upnp_service_description(
    description_url: &Url,
    lan_address: IpAddr,
    xml: &str,
) -> io::Result<UpnpService> {
    let document = roxmltree::Document::parse(xml).map_err(io::Error::other)?;
    let service = document
        .descendants()
        .filter(|node| node.has_tag_name("service"))
        .filter_map(|service| {
            let service_type = child_text(service, "serviceType")?;
            let control_url = child_text(service, "controlURL")?;
            if service_type == "urn:schemas-upnp-org:service:WANIPConnection:1"
                || service_type == "urn:schemas-upnp-org:service:WANPPPConnection:1"
            {
                Some((service_type.to_owned(), control_url.to_owned()))
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no WAN connection service"))?;
    let control_url = description_url
        .join(&service.1)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    Ok(UpnpService {
        description_url: description_url.clone(),
        control_url,
        service_type: service.0,
        lan_address,
    })
}

pub(crate) fn child_text<'a>(node: roxmltree::Node<'a, 'a>, tag: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.has_tag_name(tag))
        .and_then(|child| child.text())
        .map(str::trim)
}

pub(crate) fn upnp_add_mapping(service: &UpnpService, mapping: &UpnpPortMapping) -> io::Result<()> {
    let body = upnp_add_port_mapping_body(service, mapping);
    let response = http_post_soap(
        &service.control_url,
        &service.service_type,
        "AddPortMapping",
        &body,
        UPNP_HTTP_TIMEOUT,
    )?;

    if response.status / 100 == 2 {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {}", response.status)))
    }
}

pub(crate) fn upnp_add_port_mapping_body(
    service: &UpnpService,
    mapping: &UpnpPortMapping,
) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{service_type}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>{protocol}</NewProtocol>
<NewInternalPort>{internal_port}</NewInternalPort>
<NewInternalClient>{lan_address}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{description}</NewPortMappingDescription>
<NewLeaseDuration>{lease_duration}</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"#,
        service_type = xml_escape(&service.service_type),
        external_port = mapping.external_port,
        protocol = mapping.protocol.name(),
        internal_port = mapping.internal_port,
        lan_address = service.lan_address,
        description = xml_escape(&mapping.description),
        lease_duration = mapping.lease_duration_secs
    )
}

pub(crate) fn http_get(url: &Url, timeout: Duration) -> io::Result<UpnpHttpResponse> {
    http_request(url, "GET", &[], "", timeout)
}

pub(crate) fn http_post_soap(
    url: &Url,
    service_type: &str,
    action: &str,
    body: &str,
    timeout: Duration,
) -> io::Result<UpnpHttpResponse> {
    let soap_action = format!("\"{service_type}#{action}\"");
    http_request(
        url,
        "POST",
        &[
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", &soap_action),
        ],
        body,
        timeout,
    )
}

pub(crate) fn http_request(
    url: &Url,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
    timeout: Duration,
) -> io::Result<UpnpHttpResponse> {
    if url.scheme() != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported UPnP URL scheme {}", url.scheme()),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host in URL"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let path = http_url_path(url);
    let host_header = http_host_header(url, host, port);

    write!(
        stream,
        "{method} {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Connection: close\r\n"
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !body.is_empty() {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    write!(stream, "\r\n")?;
    if !body.is_empty() {
        stream.write_all(body.as_bytes())?;
    }
    stream.flush()?;

    read_http_response(stream)
}

pub(crate) fn http_url_path(url: &Url) -> String {
    let mut path = if url.path().is_empty() {
        "/".to_owned()
    } else {
        url.path().to_owned()
    };
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

pub(crate) fn http_host_header(url: &Url, host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };

    if Some(port) == url.port_or_known_default() && url.port().is_none() {
        host
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn read_http_response(mut stream: TcpStream) -> io::Result<UpnpHttpResponse> {
    let mut data = Vec::new();
    stream.read_to_end(&mut data)?;
    let text = String::from_utf8_lossy(&data);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    Ok(UpnpHttpResponse {
        status,
        headers,
        body: body.to_owned(),
    })
}

pub(crate) fn parse_http_headers(response: &str) -> BTreeMap<String, String> {
    response
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

pub(crate) fn local_addr_for_remote(remote: SocketAddr) -> io::Result<SocketAddr> {
    let bind = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(remote)?;
    socket.local_addr()
}

pub(crate) fn xml_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(ch),
        }
    }
    output
}

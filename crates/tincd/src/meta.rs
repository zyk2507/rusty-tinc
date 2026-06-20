use crate::*;

pub(crate) const CONNECTION_STATUS_PENDING: u32 = 0;
pub(crate) const CONNECTION_STATUS_ACTIVE: u32 = 1;
pub(crate) const CONNECTION_DUMP_STATUS_PINGED: u32 = 1 << 0;
pub(crate) const CONNECTION_DUMP_STATUS_CONTROL: u32 = 1 << 9;
pub(crate) const CONNECTION_DUMP_STATUS_PCAP: u32 = 1 << 10;
pub(crate) const CONNECTION_DUMP_STATUS_LOG: u32 = 1 << 11;
pub(crate) const CONNECTION_DUMP_STATUS_INVITATION: u32 = 1 << 13;
pub(crate) const CONNECTION_DUMP_STATUS_INVITATION_USED: u32 = 1 << 14;

#[derive(Debug)]
pub(crate) struct RuntimeMetaConnection {
    pub(crate) id: u64,
    pub(crate) stream: TcpStream,
    pub(crate) peer: SocketAddr,
    pub(crate) local: SocketAddr,
    pub(crate) bytes_read: u64,
    pub(crate) bytes_written: u64,
    pub(crate) outbound: Vec<u8>,
    pub(crate) outbound_offset: usize,
    pub(crate) status: u32,
    pub(crate) options: u32,
    pub(crate) outgoing_peer: Option<String>,
    pub(crate) outgoing_autoconnect: bool,
    pub(crate) connecting: bool,
    pub(crate) close_requested: bool,
    pub(crate) last_activity: Instant,
    pub(crate) last_ping_time: Instant,
    pub(crate) last_ping_sent: Option<Instant>,
    pub(crate) edge_peer: Option<String>,
    pub(crate) exec_proxy: Option<RuntimeExecProxyChild>,
    pub(crate) kind: RuntimeMetaConnectionKind,
}

#[derive(Debug)]
pub(crate) struct RuntimeExecProxyChild {
    pub(crate) child: Child,
}

impl RuntimeExecProxyChild {
    pub(crate) fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for RuntimeExecProxyChild {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {}
        }
    }
}

#[derive(Debug)]
pub(crate) enum RuntimeMetaConnectionKind {
    PendingIncoming {
        buffer: Vec<u8>,
    },
    Active {
        driver: RuntimeMetaDriver,
        name: Option<String>,
        proxy: ProxyHandshake,
    },
    Invitation {
        session: SptpsHandshakeSession,
        decoder: MetaStreamDecoder,
        phase: RuntimeInvitationPhase,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProxyHandshake {
    None,
    Http { buffer: Vec<u8> },
    Socks4 { buffer: Vec<u8> },
    Socks5 { buffer: Vec<u8> },
}

#[derive(Debug)]
pub(crate) enum RuntimeMetaDriver {
    Modern(MetaConnectionDriver),
    Legacy(LegacyMetaConnectionDriver),
}

impl RuntimeMetaDriver {
    pub(crate) fn modern(driver: MetaConnectionDriver) -> Self {
        Self::Modern(driver)
    }

    pub(crate) fn legacy(driver: LegacyMetaConnectionDriver) -> Self {
        Self::Legacy(driver)
    }

    pub(crate) fn initial_id_bytes(&self) -> Vec<u8> {
        match self {
            Self::Modern(driver) => driver.initial_id_bytes(),
            Self::Legacy(driver) => driver.initial_id_bytes(),
        }
    }

    pub(crate) fn incoming_initial_id_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Modern(driver) => Some(driver.initial_id_bytes()),
            Self::Legacy(_) => None,
        }
    }

    pub(crate) fn receive_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<tinc_runtime::meta::MetaConnectionStep, TincdError> {
        match self {
            Self::Modern(driver) => driver.receive_bytes(bytes).map_err(meta_connection_error),
            Self::Legacy(driver) => driver
                .receive_bytes(bytes)
                .map_err(legacy_meta_connection_error),
        }
    }

    pub(crate) fn send_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<Vec<u8>, TincdError> {
        match self {
            Self::Modern(driver) => driver
                .send_meta_message(message)
                .map_err(meta_connection_error),
            Self::Legacy(driver) => driver
                .send_meta_message(message)
                .map_err(legacy_meta_connection_error),
        }
    }

    pub(crate) fn send_tcp_packet(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, TincdError> {
        match self {
            Self::Modern(driver) => driver
                .send_tcp_packet(packet)
                .map_err(meta_connection_error),
            Self::Legacy(driver) => driver
                .send_tcp_packet(packet)
                .map_err(legacy_meta_connection_error),
        }
    }

    pub(crate) fn send_sptps_packet(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, TincdError> {
        match self {
            Self::Modern(driver) => driver
                .send_sptps_packet(packet)
                .map_err(meta_connection_error),
            Self::Legacy(driver) => driver
                .send_sptps_packet(packet)
                .map_err(legacy_meta_connection_error),
        }
    }

    pub(crate) fn is_activated(&self) -> bool {
        match self {
            Self::Modern(driver) => driver.auth().state() == MetaAuthState::Activated,
            Self::Legacy(driver) => {
                driver.auth().state() == tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated
            }
        }
    }

    pub(crate) fn is_outgoing(&self) -> bool {
        match self {
            Self::Modern(driver) => driver.auth().outgoing(),
            Self::Legacy(driver) => driver.auth().outgoing(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum RuntimeInvitationPhase {
    AwaitCookie,
    AwaitPublicKey { name: String },
}

impl RuntimeMetaConnection {
    pub(crate) fn info(&self) -> RuntimeMetaConnectionInfo {
        let status = self.connection_dump_status_bits();
        RuntimeMetaConnectionInfo {
            id: self.id,
            name: match &self.kind {
                RuntimeMetaConnectionKind::PendingIncoming { .. } => None,
                RuntimeMetaConnectionKind::Active { name, .. } => name.clone(),
                RuntimeMetaConnectionKind::Invitation { phase, .. } => match phase {
                    RuntimeInvitationPhase::AwaitCookie => None,
                    RuntimeInvitationPhase::AwaitPublicKey { name } => Some(name.clone()),
                },
            },
            peer: self.peer,
            local: self.local,
            bytes_read: self.bytes_read,
            bytes_written: self.bytes_written,
            status,
            options: self.options,
        }
    }

    pub(crate) fn connection_dump_status_bits(&self) -> u32 {
        let mut bits = 0u32;

        if self.last_ping_sent.is_some() {
            bits |= CONNECTION_DUMP_STATUS_PINGED;
        }

        if let RuntimeMetaConnectionKind::Invitation { phase, .. } = &self.kind {
            bits |= CONNECTION_DUMP_STATUS_INVITATION;
            if matches!(phase, RuntimeInvitationPhase::AwaitPublicKey { .. }) {
                bits |= CONNECTION_DUMP_STATUS_INVITATION_USED;
            }
        }

        bits
    }

    pub(crate) fn is_active_authenticated(&self) -> bool {
        let RuntimeMetaConnectionKind::Active { driver, .. } = &self.kind else {
            return false;
        };

        driver.is_activated()
    }

    pub(crate) fn active_name(&self) -> Option<&str> {
        let RuntimeMetaConnectionKind::Active {
            name: Some(name), ..
        } = &self.kind
        else {
            return None;
        };

        Some(name)
    }

    pub(crate) fn authenticated_name(&self) -> Option<&str> {
        if self.is_active_authenticated() {
            self.active_name()
        } else {
            None
        }
    }

    pub(crate) fn can_carry_data_for_peer(&self, peer: &str) -> bool {
        !self.close_requested && self.authenticated_name() == Some(peer)
    }

    pub(crate) fn is_current_edge_connection_for_peer(&self, peer: &str) -> bool {
        self.can_carry_data_for_peer(peer) && self.edge_peer.as_deref() == Some(peer)
    }

    pub(crate) fn is_outgoing(&self) -> bool {
        match &self.kind {
            RuntimeMetaConnectionKind::Active { driver, .. } => driver.is_outgoing(),
            _ => false,
        }
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        self.connecting || self.outbound_offset < self.outbound.len()
    }

    pub(crate) fn write_meta_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.compact_outbound();
        self.outbound.extend_from_slice(chunk);
        Ok(())
    }

    pub(crate) fn flush_meta_output(&mut self) -> io::Result<()> {
        if self.connecting {
            match finish_outgoing_connect_like_tinc(&self.stream) {
                Ok(true) => self.connecting = false,
                Ok(false) => return Ok(()),
                Err(error) => return Err(error),
            }
        }

        while self.pending_output_len() > 0 {
            match self.stream.write(&self.outbound[self.outbound_offset..]) {
                Ok(0) => return Ok(()),
                Ok(len) => {
                    self.bytes_written += len as u64;
                    self.outbound_offset += len;
                    if self.pending_output_len() == 0 {
                        self.outbound.clear();
                        self.outbound_offset = 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    pub(crate) fn flush_meta_output_once(&mut self) -> io::Result<RuntimeIoProgress> {
        if self.connecting {
            match finish_outgoing_connect_like_tinc(&self.stream) {
                Ok(true) => self.connecting = false,
                Ok(false) => return Ok(RuntimeIoProgress::NotReady),
                Err(error) => return Err(error),
            }
        }

        if self.pending_output_len() == 0 {
            return Ok(RuntimeIoProgress::NotReady);
        }

        match self.stream.write(&self.outbound[self.outbound_offset..]) {
            Ok(0) => Ok(RuntimeIoProgress::NotReady),
            Ok(len) => {
                self.bytes_written += len as u64;
                self.outbound_offset += len;
                if self.pending_output_len() == 0 {
                    self.outbound.clear();
                    self.outbound_offset = 0;
                }
                Ok(RuntimeIoProgress::Processed)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok(RuntimeIoProgress::NotReady)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn pending_output_len(&self) -> usize {
        self.outbound.len().saturating_sub(self.outbound_offset)
    }

    pub(crate) fn outbound_len_for_red(&self) -> usize {
        self.outbound.len()
    }

    pub(crate) fn compact_outbound(&mut self) {
        if self.outbound_offset == 0 {
            return;
        }
        if self.outbound_offset >= self.outbound.len() {
            self.outbound.clear();
        } else {
            self.outbound.drain(..self.outbound_offset);
        }
        self.outbound_offset = 0;
    }
}

pub(crate) fn queue_meta_chunk(connection: &mut RuntimeMetaConnection, chunk: &[u8]) {
    connection.compact_outbound();
    connection.outbound.extend_from_slice(chunk);
}

#[cfg(unix)]
pub(crate) fn finish_outgoing_connect_like_tinc(stream: &TcpStream) -> io::Result<bool> {
    let result = unsafe { libc::send(stream.as_raw_fd(), std::ptr::null(), 0, 0) };
    if result == 0 {
        return Ok(true);
    }
    if result > 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    if connect_probe_in_progress(&error) {
        return Ok(false);
    }
    if !connect_probe_not_connected(&error) {
        return Err(error);
    }

    match socket_error(stream.as_raw_fd())? {
        Some(error) if connect_probe_in_progress(&error) => Ok(false),
        Some(error) => Err(error),
        None => Ok(false),
    }
}

#[cfg(unix)]
fn connect_probe_in_progress(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        return true;
    }
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EINPROGRESS || code == libc::EALREADY
    )
}

#[cfg(unix)]
fn connect_probe_not_connected(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOTCONN)
}

#[cfg(unix)]
fn socket_error(fd: RawFd) -> io::Result<Option<io::Error>> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if value == 0 {
        return Ok(None);
    }
    Ok(Some(io::Error::from_raw_os_error(value)))
}

#[cfg(not(unix))]
pub(crate) fn finish_outgoing_connect_like_tinc(_stream: &TcpStream) -> io::Result<bool> {
    Ok(true)
}

pub(crate) fn send_plain_tcp_packet_on_connection(
    connection: &mut RuntimeMetaConnection,
    packet: &[u8],
    max_output_buffer_size: usize,
) -> Result<(), TincdError> {
    if random_early_drop_tcp_packet(connection, max_output_buffer_size) {
        return Ok(());
    }

    let RuntimeMetaConnectionKind::Active { driver, .. } = &mut connection.kind else {
        return Err(TincdError::MetaConnection(
            "cannot send TCP packet on pending connection".to_owned(),
        ));
    };
    let chunks = driver.send_tcp_packet(packet)?;

    for chunk in chunks {
        connection.write_meta_chunk(&chunk).map_err(listen_io)?;
    }

    Ok(())
}

pub(crate) fn send_meta_message_on_connection(
    connection: &mut RuntimeMetaConnection,
    message: &MetaMessage,
) -> Result<(), TincdError> {
    let RuntimeMetaConnectionKind::Active { driver, .. } = &mut connection.kind else {
        return Err(TincdError::MetaConnection(
            "cannot send meta message on pending connection".to_owned(),
        ));
    };
    let chunk = driver.send_meta_message(message)?;
    connection.write_meta_chunk(&chunk).map_err(listen_io)
}

pub(crate) fn send_sptps_tcp_packet_on_connection(
    connection: &mut RuntimeMetaConnection,
    packet: &[u8],
    max_output_buffer_size: usize,
) -> Result<(), TincdError> {
    if random_early_drop_tcp_packet(connection, max_output_buffer_size) {
        return Ok(());
    }

    let RuntimeMetaConnectionKind::Active { driver, .. } = &mut connection.kind else {
        return Err(TincdError::MetaConnection(
            "cannot send SPTPS TCP packet on pending connection".to_owned(),
        ));
    };
    let chunks = driver.send_sptps_packet(packet)?;

    for chunk in chunks {
        connection.write_meta_chunk(&chunk).map_err(listen_io)?;
    }

    Ok(())
}

pub(crate) fn random_early_drop_tcp_packet(
    connection: &RuntimeMetaConnection,
    max_output_buffer_size: usize,
) -> bool {
    let half = max_output_buffer_size / 2;
    let queued = connection.outbound_len_for_red();

    if queued <= half {
        return false;
    }
    if half == 0 {
        return true;
    }

    queued - half > prng_below(half)
}

pub(crate) fn random_meta_nonce_start() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::getrandom(&mut bytes).is_ok() {
        return u32::from_ne_bytes(bytes);
    }

    let fallback = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());
    fallback as u32
}

pub(crate) fn prng_below(limit: usize) -> usize {
    debug_assert!(limit > 0);
    let limit = limit as u64;
    let bins = u64::MAX / limit;
    let reject_after = bins * limit;
    let mut bytes = [0u8; 8];

    loop {
        if getrandom::getrandom(&mut bytes).is_err() {
            let fallback = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            return (fallback % limit) as usize;
        }
        let value = u64::from_ne_bytes(bytes);
        if value < reject_after {
            return (value / bins) as usize;
        }
    }
}

pub(crate) fn edge_endpoint_socket_addr(endpoint: &EdgeEndpoint) -> Option<SocketAddr> {
    let ip = endpoint.address.parse::<IpAddr>().ok()?;
    let port = endpoint.port.parse::<u16>().ok()?;
    Some(SocketAddr::new(ip, port))
}

pub(crate) fn push_unique_socket_addr(addresses: &mut Vec<SocketAddr>, address: SocketAddr) {
    if !addresses.contains(&address) {
        addresses.push(address);
    }
}

pub(crate) enum OutgoingProxyTarget {
    Tcp {
        address: SocketAddr,
        handshake: ProxyHandshake,
        request: Option<Vec<u8>>,
    },
    Exec {
        stream: TcpStream,
        child: Child,
    },
}

pub(crate) fn outgoing_proxy_connect_target(
    proxy: &ProxyConfig,
    target: SocketAddr,
    local_name: &str,
    peer_name: &str,
    netname: Option<&str>,
) -> Result<OutgoingProxyTarget, TincdError> {
    match proxy {
        ProxyConfig::None => Ok(OutgoingProxyTarget::Tcp {
            address: target,
            handshake: ProxyHandshake::None,
            request: None,
        }),
        ProxyConfig::Http { host, port, .. } => {
            let proxy_address = resolve_proxy_address("HTTP", host, port)?;
            Ok(OutgoingProxyTarget::Tcp {
                address: proxy_address,
                handshake: ProxyHandshake::Http { buffer: Vec::new() },
                request: Some(http_proxy_connect_request(target).into_bytes()),
            })
        }
        ProxyConfig::Socks4 { host, port, user } => {
            let proxy_address = resolve_proxy_address("SOCKS4", host, port)?;
            Ok(OutgoingProxyTarget::Tcp {
                address: proxy_address,
                handshake: ProxyHandshake::Socks4 { buffer: Vec::new() },
                request: Some(socks4_connect_request(target, user.as_deref())?),
            })
        }
        ProxyConfig::Socks4a { .. } => Err(TincdError::MetaConnection(
            "Proxy type not implemented yet".to_owned(),
        )),
        ProxyConfig::Socks5 {
            host,
            port,
            user,
            password,
        } => {
            let proxy_address = resolve_proxy_address("SOCKS5", host, port)?;
            Ok(OutgoingProxyTarget::Tcp {
                address: proxy_address,
                handshake: ProxyHandshake::Socks5 { buffer: Vec::new() },
                request: Some(socks5_connect_request(
                    target,
                    user.as_deref(),
                    password.as_deref(),
                )),
            })
        }
        ProxyConfig::Exec { command } => {
            let (stream, child) =
                start_exec_proxy_like_tinc(command, target, local_name, peer_name, netname)?;
            Ok(OutgoingProxyTarget::Exec { stream, child })
        }
    }
}

#[cfg(unix)]
pub(crate) fn start_exec_proxy_like_tinc(
    command: &str,
    target: SocketAddr,
    local_name: &str,
    peer_name: &str,
    netname: Option<&str>,
) -> Result<(TcpStream, Child), TincdError> {
    let mut fds = [-1; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(TincdError::MetaConnection(format!(
            "Could not create socketpair: {}",
            io::Error::last_os_error()
        )));
    }

    let child_fd = fds[1];
    let child_stdout_fd = unsafe { libc::dup(child_fd) };
    if child_stdout_fd < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(child_fd);
        }
        return Err(TincdError::MetaConnection(format!(
            "Could not duplicate proxy fd: {}",
            io::Error::last_os_error()
        )));
    }

    let (host, port) = socket_addr_host_port(target);
    let mut child_command = Command::new("/bin/sh");
    child_command
        .arg("-c")
        .arg(command)
        .stdin(unsafe { Stdio::from(File::from_raw_fd(child_fd)) })
        .stdout(unsafe { Stdio::from(File::from_raw_fd(child_stdout_fd)) })
        .env("REMOTEADDRESS", host)
        .env("REMOTEPORT", port)
        .env("NAME", local_name)
        .env("NODE", peer_name);
    if let Some(netname) = netname {
        child_command.env("NETNAME", netname);
    }

    let child = match child_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            unsafe {
                libc::close(fds[0]);
            }
            return Err(TincdError::MetaConnection(format!(
                "Could not execute {command}: {error}"
            )));
        }
    };

    set_raw_fd_cloexec(fds[0]).map_err(|error| {
        TincdError::MetaConnection(format!("Could not configure exec proxy fd: {error}"))
    })?;
    Ok((unsafe { TcpStream::from_raw_fd(fds[0]) }, child))
}

#[cfg(not(unix))]
pub(crate) fn start_exec_proxy_like_tinc(
    _command: &str,
    _target: SocketAddr,
    _local_name: &str,
    _peer_name: &str,
    _netname: Option<&str>,
) -> Result<(TcpStream, Child), TincdError> {
    Err(TincdError::MetaConnection(
        "Proxy type exec not supported on this platform!".to_owned(),
    ))
}

pub(crate) fn socket_addr_host_port(address: SocketAddr) -> (String, String) {
    (address.ip().to_string(), address.port().to_string())
}

pub(crate) fn resolve_proxy_address(
    kind: &str,
    host: &str,
    port: &str,
) -> Result<SocketAddr, TincdError> {
    let proxy_endpoint = format!("{host}:{port}");
    proxy_endpoint
        .to_socket_addrs()
        .map_err(|error| {
            TincdError::MetaConnection(format!(
                "could not resolve {kind} proxy {host} port {port}: {error}"
            ))
        })?
        .next()
        .ok_or_else(|| {
            TincdError::MetaConnection(format!("could not resolve {kind} proxy {host} port {port}"))
        })
}

pub(crate) fn http_proxy_connect_request(target: SocketAddr) -> String {
    let host = match target.ip() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    format!("CONNECT {host}:{} HTTP/1.1\r\n\r", target.port())
}

pub(crate) const SOCKS4_RESPONSE_LEN: usize = 8;

pub(crate) fn socks4_connect_request(
    target: SocketAddr,
    user: Option<&str>,
) -> Result<Vec<u8>, TincdError> {
    let SocketAddr::V4(address) = target else {
        return Err(TincdError::MetaConnection(
            "SOCKS 4 only supports IPv4 addresses".to_owned(),
        ));
    };
    let mut request = Vec::with_capacity(9 + user.map_or(0, str::len));
    request.push(4);
    request.push(1);
    request.extend_from_slice(&address.port().to_be_bytes());
    request.extend_from_slice(&address.ip().octets());
    if let Some(user) = user {
        request.extend_from_slice(user.as_bytes());
    }
    request.push(0);
    Ok(request)
}

pub(crate) fn validate_socks4_response_like_tinc(response: &[u8]) -> Result<(), TincdError> {
    if response.len() < SOCKS4_RESPONSE_LEN {
        return Err(TincdError::MetaConnection(
            "Received short response from proxy".to_owned(),
        ));
    }
    if response[0] != 0 {
        return Err(TincdError::MetaConnection(
            "Bad response from SOCKS4 proxy".to_owned(),
        ));
    }
    if response[1] != 0x5a {
        return Err(TincdError::MetaConnection(
            "Proxy request rejected".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn socks5_connect_request(
    target: SocketAddr,
    user: Option<&str>,
    password: Option<&str>,
) -> Vec<u8> {
    let password_auth = user.is_some() && password.is_some();
    let mut request = Vec::new();
    request.push(5);
    request.push(1);
    request.push(if password_auth { 2 } else { 0 });
    if password_auth {
        let user = user.unwrap_or_default().as_bytes();
        let password = password.unwrap_or_default().as_bytes();
        request.push(1);
        request.push(user.len() as u8);
        request.extend_from_slice(user);
        request.push(password.len() as u8);
        request.extend_from_slice(password);
    }
    request.extend_from_slice(&[5, 1, 0]);
    match target {
        SocketAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    request
}

pub(crate) fn socks5_response_len(response: &[u8]) -> usize {
    if response.len() < 2 {
        return 0;
    }
    let addr_type_offset = match response[1] {
        0 => 5,
        2 => 7,
        _ => return 2,
    };
    if response.len() <= addr_type_offset {
        return 0;
    }
    match response[addr_type_offset] {
        1 => addr_type_offset + 7,
        4 => addr_type_offset + 19,
        _ => addr_type_offset + 1,
    }
}

pub(crate) fn validate_socks5_response_like_tinc(response: &[u8]) -> Result<(), TincdError> {
    let required = socks5_response_len(response);
    if required == 0 || response.len() < required {
        return Err(TincdError::MetaConnection(
            "Received short response from proxy".to_owned(),
        ));
    }
    if response[0] != 5 {
        return Err(TincdError::MetaConnection(
            "Invalid response from proxy server".to_owned(),
        ));
    }
    if response[1] == 0xff {
        return Err(TincdError::MetaConnection(
            "Proxy request rejected: unsuitable authentication method".to_owned(),
        ));
    }
    let conn_offset = match response[1] {
        0 => 2,
        2 => {
            if response.len() < 4 {
                return Err(TincdError::MetaConnection(
                    "Received short response from proxy".to_owned(),
                ));
            }
            if response[2] != 1 {
                return Err(TincdError::MetaConnection(
                    "Invalid proxy authentication protocol version".to_owned(),
                ));
            }
            if response[3] != 0 {
                return Err(TincdError::MetaConnection(
                    "Proxy authentication failed".to_owned(),
                ));
            }
            4
        }
        _ => {
            return Err(TincdError::MetaConnection(
                "Unsupported authentication method".to_owned(),
            ));
        }
    };
    if response[conn_offset] != 5 {
        return Err(TincdError::MetaConnection(
            "Invalid response from proxy server".to_owned(),
        ));
    }
    if response[conn_offset + 1] != 0 {
        return Err(TincdError::MetaConnection(
            "Proxy request rejected".to_owned(),
        ));
    }
    let addr_type = response[conn_offset + 3];
    if addr_type != 1 && addr_type != 4 {
        return Err(TincdError::MetaConnection(format!(
            "Unsupported address type 0x{:x} from proxy server",
            addr_type
        )));
    }
    Ok(())
}

pub(crate) fn promote_recent_address(addresses: &mut Vec<SocketAddr>, address: SocketAddr) {
    if let Some(position) = addresses.iter().position(|candidate| *candidate == address) {
        if position == 0 {
            return;
        }
        addresses.remove(position);
    } else if addresses.len() >= MAX_CACHED_ADDRESSES {
        addresses.pop();
    }
    addresses.insert(0, address);
}

pub(crate) fn read_tinc_address_cache(path: &Path) -> Vec<SocketAddr> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    decode_tinc_address_cache(&bytes)
}

pub(crate) fn write_tinc_address_cache(path: &Path, addresses: &[SocketAddr]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, encode_tinc_address_cache(addresses))
}

pub(crate) fn encode_tinc_address_cache(addresses: &[SocketAddr]) -> Vec<u8> {
    #[cfg(unix)]
    {
        let mut bytes = Vec::with_capacity(8 + MAX_CACHED_ADDRESSES * c_sockaddr_cache_slot_len());
        bytes.extend_from_slice(&ADDRESS_CACHE_VERSION.to_ne_bytes());
        bytes.extend_from_slice(&(addresses.len().min(MAX_CACHED_ADDRESSES) as u32).to_ne_bytes());
        for address in addresses.iter().take(MAX_CACHED_ADDRESSES) {
            bytes.extend_from_slice(&encode_c_sockaddr_slot(*address));
        }
        while bytes.len() < 8 + MAX_CACHED_ADDRESSES * c_sockaddr_cache_slot_len() {
            bytes.extend_from_slice(&vec![0; c_sockaddr_cache_slot_len()]);
        }
        bytes
    }
    #[cfg(not(unix))]
    {
        let _ = addresses;
        Vec::new()
    }
}

pub(crate) fn decode_tinc_address_cache(bytes: &[u8]) -> Vec<SocketAddr> {
    #[cfg(unix)]
    {
        let slot_len = c_sockaddr_cache_slot_len();
        let expected = 8 + MAX_CACHED_ADDRESSES * slot_len;
        if bytes.len() < expected {
            return Vec::new();
        }

        let version = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let used = u32::from_ne_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if version != ADDRESS_CACHE_VERSION || used > MAX_CACHED_ADDRESSES {
            return Vec::new();
        }

        let mut addresses = Vec::new();
        for index in 0..used {
            let offset = 8 + index * slot_len;
            if let Some(address) = decode_c_sockaddr_slot(&bytes[offset..offset + slot_len]) {
                push_unique_socket_addr(&mut addresses, address);
            }
        }
        addresses
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        Vec::new()
    }
}

#[cfg(unix)]
pub(crate) fn c_sockaddr_cache_slot_len() -> usize {
    let sockaddr_unknown_size = 8 + 2 * std::mem::size_of::<*const libc::c_char>();
    let size = std::mem::size_of::<libc::sockaddr_in6>().max(sockaddr_unknown_size);
    let align =
        std::mem::align_of::<libc::sockaddr_in6>().max(std::mem::align_of::<*const libc::c_char>());
    size.div_ceil(align) * align
}

#[cfg(unix)]
pub(crate) fn encode_c_sockaddr_slot(address: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0; c_sockaddr_cache_slot_len()];
    match address {
        SocketAddr::V4(address) => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const libc::sockaddr_in).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            };
            bytes[..raw_bytes.len()].copy_from_slice(raw_bytes);
        }
        SocketAddr::V6(address) => {
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: address.ip().octets(),
            };
            raw.sin6_scope_id = address.scope_id();
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const libc::sockaddr_in6).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            };
            bytes[..raw_bytes.len()].copy_from_slice(raw_bytes);
        }
    }
    bytes
}

#[cfg(unix)]
pub(crate) fn decode_c_sockaddr_slot(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < c_sockaddr_cache_slot_len() {
        return None;
    }
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?) as libc::c_int;
    match family {
        libc::AF_INET => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut raw as *mut libc::sockaddr_in).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            let ip = Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr));
            let port = u16::from_be(raw.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut raw as *mut libc::sockaddr_in6).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
            let port = u16::from_be(raw.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn system_udp_path_mtu(target: SocketAddr) -> Option<usize> {
    if !target.is_ipv4() {
        return None;
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return None;
    }

    let result = (|| {
        let (raw_address, raw_length) = socket_addr_to_raw(&target);
        if unsafe {
            libc::connect(
                fd,
                (&raw_address as *const libc::sockaddr_storage).cast(),
                raw_length,
            )
        } < 0
        {
            return None;
        }

        let mut ip_mtu: libc::c_int = 0;
        let mut ip_mtu_len = std::mem::size_of_val(&ip_mtu) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU,
                (&mut ip_mtu as *mut libc::c_int).cast(),
                &mut ip_mtu_len,
            )
        } < 0
        {
            return None;
        }

        usize::try_from(ip_mtu).ok()
    })();

    unsafe {
        libc::close(fd);
    }

    result
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn system_udp_path_mtu(_target: SocketAddr) -> Option<usize> {
    None
}

pub(crate) fn pmtu_initial_probe_len(min_mtu: usize, max_mtu: usize, mtu_probes: i32) -> usize {
    let min_mtu = min_mtu.max(MIN_MTU);
    let interval = max_mtu.saturating_sub(min_mtu) as f32;
    let cycle_position = (PMTU_PROBES_PER_CYCLE - (mtu_probes % PMTU_PROBES_PER_CYCLE) - 1) as f32;
    let multiplier = if max_mtu == DEFAULT_MTU { 0.97 } else { 1.0 };
    let offset = if interval > 0.0 {
        interval
            .powf(multiplier * cycle_position / (PMTU_PROBES_PER_CYCLE - 1) as f32)
            .round()
            .max(0.0) as usize
    } else {
        0
    };

    min_mtu + offset
}

pub(crate) fn udp_probe_request_payload(len: usize) -> Vec<u8> {
    let len = len.clamp(UDP_PROBE_MIN_SIZE, DEFAULT_MTU);
    let mut payload = vec![0; len];
    for byte in payload.iter_mut().skip(14) {
        *byte = prng_below(256) as u8;
    }
    payload
}

pub(crate) fn is_udp_probe_payload(data: &[u8]) -> bool {
    data.len() > UDP_PROBE_ETHERTYPE_OFFSET + 1
        && data[UDP_PROBE_ETHERTYPE_OFFSET] == 0
        && data[UDP_PROBE_ETHERTYPE_OFFSET + 1] == 0
}

pub(crate) fn udp_probe_reply_payload(request: &[u8], peer_options: u32) -> Option<Vec<u8>> {
    if request.first().copied()? != 0 {
        return None;
    }

    let mut reply = request.to_vec();
    if option_version(peer_options) >= 3 {
        reply.resize(UDP_PROBE_MIN_SIZE, 0);
        reply[0] = 2;
        let len = u16::try_from(request.len()).unwrap_or(u16::MAX);
        reply[1..3].copy_from_slice(&len.to_be_bytes());
        reply.truncate(UDP_PROBE_MIN_SIZE);
    } else {
        reply[0] = 1;
    }
    Some(reply)
}

pub(crate) fn udp_probe_reply_len(payload: &[u8]) -> usize {
    if payload.first() == Some(&2) && payload.len() >= 3 {
        u16::from_be_bytes([payload[1], payload[2]]) as usize
    } else {
        payload.len()
    }
}

pub(crate) fn tincd_transport_error(error: TincdError) -> TransportError {
    TransportError::Io(io::Error::other(error.to_string()))
}

pub(crate) fn mark_meta_connection_closed_on_scoped_error_like_tinc(
    connection: &mut RuntimeMetaConnection,
    error: TincdError,
) -> Result<bool, TransportError> {
    if is_meta_connection_scoped_error(&error) {
        connection.close_requested = true;
        return Ok(true);
    }

    Err(tincd_transport_error(error))
}

pub(crate) fn mark_meta_connection_closed_on_scoped_error_like_tinc_for_daemon(
    connection: &mut RuntimeMetaConnection,
    error: TincdError,
) -> Result<bool, TincdError> {
    if is_meta_connection_scoped_error(&error) {
        connection.close_requested = true;
        return Ok(true);
    }

    Err(error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeMetaConnectionInfo {
    pub id: u64,
    pub name: Option<String>,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub status: u32,
    pub options: u32,
}

pub(crate) fn meta_connection_error(error: MetaConnectionError) -> TincdError {
    TincdError::MetaConnection(error.to_string())
}

pub(crate) fn legacy_meta_connection_error(error: LegacyMetaConnectionError) -> TincdError {
    TincdError::MetaConnection(error.to_string())
}

pub(crate) fn is_meta_connection_scoped_error(error: &TincdError) -> bool {
    matches!(
        error,
        TincdError::ListenIo(_)
            | TincdError::MetaConnection(_)
            | TincdError::LegacyPacket(_)
            | TincdError::UnknownPeerKey(_)
    )
}

pub(crate) fn invitation_sptps_error(error: SptpsError) -> TincdError {
    TincdError::MetaConnection(format!("invitation SPTPS failed: {error}"))
}

pub(crate) fn sptps_key_exchange_error(error: SptpsKeyExchangeError) -> TincdError {
    TincdError::RuntimeState(error.to_string())
}

pub(crate) fn is_recoverable_sptps_answer_key_error(error: &SptpsKeyExchangeError) -> bool {
    matches!(
        error,
        SptpsKeyExchangeError::MissingSession(_)
            | SptpsKeyExchangeError::Protocol(_)
            | SptpsKeyExchangeError::Sptps(_)
    )
}

pub(crate) fn is_recoverable_sptps_request_key_error(error: &SptpsKeyExchangeError) -> bool {
    matches!(
        error,
        SptpsKeyExchangeError::Protocol(_) | SptpsKeyExchangeError::Sptps(_)
    )
}

pub(crate) fn legacy_packet_error(error: LegacyPacketError) -> TincdError {
    TincdError::LegacyPacket(error)
}

pub(crate) fn is_recoverable_legacy_answer_key_error(error: &TincdError) -> bool {
    matches!(
        error,
        TincdError::LegacyPacket(
            LegacyPacketError::InvalidCompression(_)
                | LegacyPacketError::InvalidKeyMaterialLength { .. }
                | LegacyPacketError::UnsupportedCompression(_)
        )
    )
}

pub(crate) fn engine_error(error: EngineError) -> TincdError {
    TincdError::RuntimeState(error.to_string())
}

pub(crate) fn device_error(action: &str, error: DeviceError) -> TincdError {
    TincdError::RuntimeState(format!("device {action} failed: {error}"))
}

pub(crate) fn trim_meta_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

pub(crate) fn packet_summary(packet: &VpnPacket) -> String {
    packet_data_summary(&packet.data, packet.priority)
}

pub(crate) fn packet_data_summary(data: &[u8], priority: i32) -> String {
    let mut summary = format!("len={} priority={priority}", data.len());

    if data.len() >= 14 {
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        summary.push_str(&format!(
            " ethertype=0x{ethertype:04x} dst={} src={}",
            format_mac(&data[0..6]),
            format_mac(&data[6..12])
        ));
        if ethertype == 0x0800 && data.len() >= 34 {
            summary.push_str(&format!(
                " ipv4={}.{}.{}.{}->{}.{}.{}.{}",
                data[26], data[27], data[28], data[29], data[30], data[31], data[32], data[33]
            ));
        }
        if ethertype == 0x86dd && data.len() >= 54 {
            summary.push_str(" ipv6");
        }
    } else if data.len() >= 20 && data[0] >> 4 == 4 {
        summary.push_str(&format!(
            " bare-ipv4={}.{}.{}.{}->{}.{}.{}.{}",
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]
        ));
    } else if data.len() >= 40 && data[0] >> 4 == 6 {
        summary.push_str(" bare-ipv6");
    }

    summary
}

pub(crate) fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub(crate) fn should_broadcast_runtime_message(message: &MetaMessage) -> bool {
    matches!(
        message,
        MetaMessage::AddSubnet(_)
            | MetaMessage::DeleteSubnet(_)
            | MetaMessage::AddEdge(_)
            | MetaMessage::DeleteEdge(_)
            | MetaMessage::KeyChanged(_)
    )
}

pub(crate) fn is_sptps_key_exchange_message(message: &MetaMessage) -> bool {
    match message {
        MetaMessage::RequestKey(message) => message
            .extension
            .as_ref()
            .and_then(|extension| Request::try_from(extension.request).ok())
            .is_some_and(|request| matches!(request, Request::RequestKey | Request::SptpsPacket)),
        MetaMessage::AnswerKey(message) => message.is_sptps_handshake(),
        _ => false,
    }
}

pub(crate) fn request_key_extension_request(message: &RequestKeyMessage) -> Option<Request> {
    message
        .extension
        .as_ref()
        .and_then(|extension| Request::try_from(extension.request).ok())
}

use crate::*;
use rand_core::OsRng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use std::fs;
#[cfg(unix)]
use std::sync::atomic::{AtomicU16, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use tinc_core::config::ConfigSource;
use tinc_core::route::{ETH_HLEN, ETH_P_IP, ethernet_packet};
use tinc_core::subnet::MacAddr;
use tinc_runtime::config::SandboxLevel;
use tinc_runtime::device::DeviceKind;
use tinc_runtime::legacy_meta::{
    LegacyMetaError, legacy_meta_generate_rsa_key_material, legacy_meta_public_encrypt,
};
use tinc_runtime::sptps::ED25519_SEED_LEN;

mod autoconnect;
mod config_cli;
mod control;
mod device;
mod key_meta;
mod listeners_server;
mod misc;
mod outgoing;
mod platform;
mod scripts_logging;
mod transport_legacy;
mod transport_sptps;
mod transport_udp_pmtu;
mod upnp;

#[derive(Clone, Debug)]
struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedLogBuffer {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn output(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for SharedLogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = env::var_os(key);
        // SAFETY: tests use this guard for narrow startup-env checks and restore
        // the previous value in Drop, matching tincd's single-threaded startup use.
        unsafe {
            env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: see EnvVarGuard::set.
        unsafe {
            if let Some(previous) = &self.previous {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }
}

#[cfg(unix)]
static SYSTEMD_LISTEN_TEST_PORT: AtomicU16 = AtomicU16::new(20_000);

#[cfg(unix)]
fn bind_systemd_test_tcp_listener(index: u8) -> TcpListener {
    let address = Ipv4Addr::new(127, 77, index, 1);
    for _ in 0..2000 {
        let port = SYSTEMD_LISTEN_TEST_PORT.fetch_add(1, AtomicOrdering::Relaxed);
        let socket = SocketAddr::new(IpAddr::V4(address), port);
        let Ok(listener) = TcpListener::bind(socket) else {
            continue;
        };
        match UdpSocket::bind(socket) {
            Ok(udp_probe) => {
                drop(udp_probe);
                return listener;
            }
            Err(_) => drop(listener),
        }
    }

    panic!("failed to allocate a systemd listen test socket for {address}");
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn drive_until_no_meta_connections(runtime: &mut RuntimeDaemonState) {
    let deadline = Instant::now() + StdDuration::from_secs(1);
    loop {
        runtime.poll_once().unwrap();
        if runtime.meta_connection_infos().is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not close the pending meta connection"
        );
        thread::sleep(StdDuration::from_millis(10));
    }
}

fn drive_outgoing_meta_output(runtime: &mut RuntimeDaemonState) {
    let deadline = Instant::now() + StdDuration::from_secs(1);
    loop {
        runtime.poll_once().unwrap();
        runtime.flush_meta_outputs().unwrap();
        if runtime
            .meta_connections
            .iter()
            .any(|connection| !connection.connecting && connection.bytes_written > 0)
        {
            return;
        }
        assert!(
            !runtime.meta_connections.is_empty(),
            "outgoing meta connection closed before writing the initial prelude"
        );
        assert!(
            Instant::now() < deadline,
            "outgoing meta connection did not write the initial prelude"
        );
        thread::sleep(StdDuration::from_millis(10));
    }
}

fn flush_outgoing_meta_output(runtime: &mut RuntimeDaemonState) {
    let deadline = Instant::now() + StdDuration::from_secs(1);
    loop {
        runtime.flush_meta_outputs().unwrap();
        if runtime
            .meta_connections
            .iter()
            .any(|connection| !connection.connecting && connection.bytes_written > 0)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "outgoing meta connection did not flush the initial prelude"
        );
        thread::sleep(StdDuration::from_millis(10));
    }
}

fn accept_after_runtime_progress(
    listener: &TcpListener,
    runtime: &mut RuntimeDaemonState,
) -> (TcpStream, SocketAddr) {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + StdDuration::from_secs(1);
    loop {
        match listener.accept() {
            Ok(accepted) => {
                listener.set_nonblocking(false).unwrap();
                accepted
                    .0
                    .set_read_timeout(Some(StdDuration::from_secs(1)))
                    .unwrap();
                return accepted;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("failed to accept outgoing test connection: {error}"),
        }
        runtime.poll_once().unwrap();
        assert!(
            Instant::now() < deadline,
            "runtime did not connect to the expected listener"
        );
        thread::sleep(StdDuration::from_millis(10));
    }
}

fn config_tree(configs: &[(&str, &str)]) -> ConfigTree {
    let mut tree = ConfigTree::new();

    for (line, (variable, value)) in configs.iter().enumerate() {
        tree.add(Config::new(
            *variable,
            *value,
            ConfigSource::file("tinc.conf", i32::try_from(line + 1).unwrap()),
        ));
    }

    tree
}

#[cfg(target_os = "linux")]
fn pathname_sockaddr_un(path: &Path) -> libc::sockaddr_un {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    assert!(bytes.len() < address.sun_path.len());
    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }
    address
}

#[cfg(target_os = "linux")]
fn sendto_unix_sockaddr(fd: RawFd, address: &libc::sockaddr_un, payload: &[u8]) -> io::Result<()> {
    let sent = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr().cast::<libc::c_void>(),
            payload.len(),
            0,
            (address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        Err(io::Error::last_os_error())
    } else if sent as usize != payload.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short sendto to UML data socket",
        ))
    } else {
        Ok(())
    }
}

fn temp_confbase(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!("tincd-{test_name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(path.join("hosts")).unwrap();
    path
}

fn test_key(byte: u8) -> TincEd25519PrivateKey {
    TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
}

fn test_rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 1024).unwrap()
}

fn test_legacy_rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new_with_exp(&mut OsRng, 1024, &legacy_rsa_exponent()).unwrap()
}

fn empty_runtime_keys() -> RuntimeKeys {
    RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    }
}

fn rsa_hex(value: &BigUint) -> String {
    format!("{value:X}")
}

#[cfg(target_os = "linux")]
fn set_file_mtime(path: &Path, seconds: libc::time_t) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    let result = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(
        0,
        result,
        "utimensat failed: {}",
        io::Error::last_os_error()
    );
}

fn test_runtime_listen_socket() -> io::Result<RuntimeListenSocket> {
    let tcp = TcpListener::bind("127.0.0.1:0")?;
    let address = tcp.local_addr()?;
    let udp = UdpSocket::bind(address)?;
    tcp.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;

    Ok(RuntimeListenSocket {
        tcp,
        udp,
        address,
        bind_to: true,
        priority: Cell::new(0),
    })
}

fn active_sptps_runtime_waiting_for_beta_key()
-> Option<(RuntimeDaemonState, TcpStream, MetaConnectionDriver)> {
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((beta_stream, beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return None;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.sptps = true;
    beta.route.next_hop = Some("beta".to_owned());

    runtime
        .handle_sptps_key_actions(vec![RuntimeSptpsKeyAction {
            peer: "beta".to_owned(),
            next_hop: "beta".to_owned(),
        }])
        .unwrap();

    Some((runtime, beta_stream, beta_driver))
}

#[cfg(target_os = "linux")]
fn test_runtime_ipv6_listen_socket_with_mtu(mtu: i32) -> io::Result<RuntimeListenSocket> {
    let tcp = TcpListener::bind("[::1]:0")?;
    let address = tcp.local_addr()?;
    let udp = UdpSocket::bind(address)?;
    set_test_ipv6_socket_mtu(&udp, mtu)?;
    tcp.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;

    Ok(RuntimeListenSocket {
        tcp,
        udp,
        address,
        bind_to: true,
        priority: Cell::new(0),
    })
}

#[cfg(target_os = "linux")]
fn set_test_ipv6_socket_mtu(socket: &UdpSocket, mtu: i32) -> io::Result<()> {
    let discover: libc::c_int = libc::IP_PMTUDISC_DO;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            (&discover as *const libc::c_int).cast(),
            std::mem::size_of_val(&discover) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU,
            (&mtu as *const libc::c_int).cast(),
            std::mem::size_of_val(&mtu) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn complete_sptps_udp_exchange(alpha: &mut RuntimeDaemonState, beta: &mut RuntimeDaemonState) {
    complete_sptps_udp_exchange_between(alpha, "beta", beta, "alpha");
}

fn complete_sptps_udp_exchange_between(
    alpha: &mut RuntimeDaemonState,
    alpha_peer: &str,
    beta: &mut RuntimeDaemonState,
    beta_peer: &str,
) {
    let alpha_request = alpha.start_sptps_key_exchange(alpha_peer).unwrap();
    assert_eq!(1, alpha_request.len());

    let beta_answer = beta
        .receive_sptps_key_exchange_message(&alpha_request[0])
        .unwrap();
    assert_eq!(1, beta_answer.len());

    let alpha_answer = alpha
        .receive_sptps_key_exchange_message(&beta_answer[0])
        .unwrap();
    assert_eq!(1, alpha_answer.len());

    let beta_final = beta
        .receive_sptps_key_exchange_message(&alpha_answer[0])
        .unwrap();
    assert_eq!(1, beta_final.len());
    assert!(beta.packet_codec.peer(beta_peer).is_some());

    let alpha_final = alpha
        .receive_sptps_key_exchange_message(&beta_final[0])
        .unwrap();
    assert!(alpha_final.is_empty());
    assert!(alpha.packet_codec.peer(alpha_peer).is_some());
}

fn recv_sptps_probe_payload(
    receiver: &mut RuntimeDaemonState,
    peer: &str,
    expected_source: SocketAddr,
) -> Vec<u8> {
    let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match receiver.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(expected_source, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive SPTPS probe datagram: {error}"),
        }
    };
    let record = receiver
        .packet_codec
        .decode_record(peer, &buffer[..len])
        .unwrap();
    assert_eq!(SPTPS_UDP_PROBE_TYPE, record.record_type);
    record.payload
}

fn test_ipv4_payload(destination: [u8; 4]) -> Vec<u8> {
    let mut payload = vec![0; 20];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&20u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 17;
    payload[12..16].copy_from_slice(&[192, 0, 2, 1]);
    payload[16..20].copy_from_slice(&destination);
    payload
}

fn test_ipv4_ethernet_packet(destination: [u8; 4]) -> Vec<u8> {
    let payload = test_ipv4_payload(destination);
    ethernet_packet(
        MacAddr::new([0, 1, 2, 3, 4, 5]),
        MacAddr::new([6, 7, 8, 9, 10, 11]),
        ETH_P_IP,
        &payload,
    )
}

fn test_ipv4_router_packet(destination: [u8; 4]) -> Vec<u8> {
    let payload = test_ipv4_payload(destination);
    let mut packet = vec![0; ETH_HLEN - 2];
    packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
    packet.extend_from_slice(&payload);
    packet
}

fn flatten_outbound(outbound: Vec<Vec<u8>>) -> Vec<u8> {
    outbound.into_iter().flatten().collect()
}

fn established_meta_driver_pair(
    alpha_key: TincEd25519PrivateKey,
    beta_key: TincEd25519PrivateKey,
) -> (MetaConnectionDriver, MetaConnectionDriver) {
    established_meta_driver_pair_for("beta", alpha_key, beta_key)
}

fn established_meta_driver_pair_for(
    peer: &str,
    alpha_key: TincEd25519PrivateKey,
    peer_key: TincEd25519PrivateKey,
) -> (MetaConnectionDriver, MetaConnectionDriver) {
    let mut alpha = MetaConnectionDriver::new(MetaConnectionAuth::new(
        "alpha",
        true,
        alpha_key.clone(),
        peer_key.public_key(),
        "655",
        0,
        (PROT_MINOR as u32) << 24,
    ));
    let mut remote = MetaConnectionDriver::new(MetaConnectionAuth::new(
        peer,
        false,
        peer_key,
        alpha_key.public_key(),
        "655",
        0,
        (PROT_MINOR as u32) << 24,
    ));

    let alpha_id = alpha.initial_id_bytes();
    let remote_after_id = remote.receive_bytes(&alpha_id).unwrap();
    let mut remote_to_alpha = remote.initial_id_bytes();
    remote_to_alpha.extend(flatten_outbound(remote_after_id.outbound));

    let alpha_after_remote = alpha.receive_bytes(&remote_to_alpha).unwrap();
    let remote_after_alpha = remote
        .receive_bytes(&flatten_outbound(alpha_after_remote.outbound))
        .unwrap();
    let alpha_after_remote = alpha
        .receive_bytes(&flatten_outbound(remote_after_alpha.outbound))
        .unwrap();
    remote
        .receive_bytes(&flatten_outbound(alpha_after_remote.outbound))
        .unwrap();

    (alpha, remote)
}

fn is_sptps_initial_req_key(event: &MetaConnectionEvent, from: &str, to: &str) -> bool {
    let MetaConnectionEvent::Message(MetaMessage::RequestKey(request)) = event else {
        return false;
    };
    if request.from != from || request.to != to {
        return false;
    }
    let Ok(payload) = request.decode_sptps_payload() else {
        return false;
    };

    payload.kind == tinc_core::protocol::SptpsKeyPayloadKind::InitialRequest
}

fn is_sptps_tcp_packet(event: &MetaConnectionEvent) -> bool {
    matches!(event, MetaConnectionEvent::SptpsPacket(_))
}

fn read_meta_events_until<F>(
    stream: &mut TcpStream,
    driver: &mut MetaConnectionDriver,
    predicate: F,
) -> Vec<MetaConnectionEvent>
where
    F: Fn(&MetaConnectionEvent) -> bool,
{
    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);

    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                events.extend(driver.receive_bytes(&buffer[..len]).unwrap().events);
                if events.iter().any(&predicate) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read meta events: {error}"),
        }
    }

    events
}

fn flush_then_read_meta_events_until<F>(
    runtime: &mut RuntimeDaemonState,
    stream: &mut TcpStream,
    driver: &mut MetaConnectionDriver,
    predicate: F,
) -> Vec<MetaConnectionEvent>
where
    F: Fn(&MetaConnectionEvent) -> bool,
{
    runtime.flush_meta_outputs().unwrap();
    read_meta_events_until(stream, driver, predicate)
}

fn active_runtime_connection(
    peer: &str,
    alpha_key: TincEd25519PrivateKey,
    peer_key: TincEd25519PrivateKey,
) -> Option<(TcpStream, MetaConnectionDriver, RuntimeMetaConnection)> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("failed to bind active connection test listener: {error}"),
    };
    let remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, daemon_peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    remote_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let daemon_local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, remote_driver) = established_meta_driver_pair_for(peer, alpha_key, peer_key);

    Some((
        remote_stream,
        remote_driver,
        RuntimeMetaConnection {
            id: 0,
            stream: daemon_stream,
            peer: daemon_peer,
            local: daemon_local,
            bytes_read: 0,
            bytes_written: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            status: CONNECTION_STATUS_ACTIVE,
            options: (PROT_MINOR as u32) << 24,
            outgoing_peer: None,
            outgoing_autoconnect: false,
            connecting: false,
            close_requested: false,
            last_activity: Instant::now(),
            last_ping_time: Instant::now(),
            last_ping_sent: None,
            edge_peer: None,
            exec_proxy: None,
            kind: RuntimeMetaConnectionKind::Active {
                driver: RuntimeMetaDriver::modern(alpha_driver),
                name: Some(peer.to_owned()),
                proxy: ProxyHandshake::None,
            },
        },
    ))
}

fn established_legacy_meta_driver_pair_for(
    peer: &str,
    alpha_rsa: RsaPrivateKey,
    peer_rsa: RsaPrivateKey,
) -> (LegacyMetaConnectionDriver, LegacyMetaConnectionDriver) {
    let mut alpha = LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            "alpha",
            true,
            LegacyMetaPrivateKey::Pem(alpha_rsa.clone()),
            RsaPublicKey::from(&peer_rsa),
            "655",
            0,
            0,
        )
        .with_protocol_minor(LEGACY_META_PROTOCOL_MINOR),
    );
    let mut remote = LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            peer,
            false,
            LegacyMetaPrivateKey::Pem(peer_rsa),
            RsaPublicKey::from(&alpha_rsa),
            "655",
            0,
            0,
        )
        .with_protocol_minor(LEGACY_META_PROTOCOL_MINOR),
    );

    let mut to_remote = alpha.initial_id_bytes();
    let mut to_alpha = Vec::new();
    for _ in 0..8 {
        if !to_remote.is_empty() {
            let step = remote.receive_bytes(&to_remote).unwrap();
            to_alpha = flatten_outbound(step.outbound);
            to_remote.clear();
        }
        if alpha.auth().state() == tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated
            && remote.auth().state() == tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated
        {
            break;
        }
        if !to_alpha.is_empty() {
            let step = alpha.receive_bytes(&to_alpha).unwrap();
            to_remote = flatten_outbound(step.outbound);
            to_alpha.clear();
        }
        if alpha.auth().state() == tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated
            && remote.auth().state() == tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated
        {
            break;
        }
    }

    assert_eq!(
        tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated,
        alpha.auth().state()
    );
    assert_eq!(
        tinc_runtime::legacy_meta::LegacyMetaAuthState::Activated,
        remote.auth().state()
    );

    (alpha, remote)
}

fn active_legacy_runtime_connection(
    peer: &str,
    alpha_rsa: RsaPrivateKey,
    peer_rsa: RsaPrivateKey,
) -> Option<(TcpStream, LegacyMetaConnectionDriver, RuntimeMetaConnection)> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("failed to bind active legacy connection test listener: {error}"),
    };
    let remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, daemon_peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    remote_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let daemon_local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, remote_driver) =
        established_legacy_meta_driver_pair_for(peer, alpha_rsa, peer_rsa);

    Some((
        remote_stream,
        remote_driver,
        RuntimeMetaConnection {
            id: 0,
            stream: daemon_stream,
            peer: daemon_peer,
            local: daemon_local,
            bytes_read: 0,
            bytes_written: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            status: CONNECTION_STATUS_ACTIVE,
            options: 0,
            outgoing_peer: None,
            outgoing_autoconnect: false,
            connecting: false,
            close_requested: false,
            last_activity: Instant::now(),
            last_ping_time: Instant::now(),
            last_ping_sent: None,
            edge_peer: None,
            exec_proxy: None,
            kind: RuntimeMetaConnectionKind::Active {
                driver: RuntimeMetaDriver::legacy(alpha_driver),
                name: Some(peer.to_owned()),
                proxy: ProxyHandshake::None,
            },
        },
    ))
}

fn read_test_tcp_line(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> String {
    loop {
        if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            let line = buffer.drain(..=newline).collect::<Vec<_>>();
            return String::from_utf8(trim_meta_line(&line).to_vec()).unwrap();
        }

        read_test_tcp_more(stream, buffer);
    }
}

fn read_test_tcp_more(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> usize {
    let mut chunk = [0u8; 4096];
    let len = stream.read(&mut chunk).unwrap();
    buffer.extend_from_slice(&chunk[..len]);
    len
}

fn read_test_tcp_available(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> usize {
    let mut chunk = [0u8; 4096];
    stream.set_nonblocking(true).unwrap();

    let result = match stream.read(&mut chunk) {
        Ok(len) => {
            buffer.extend_from_slice(&chunk[..len]);
            len
        }
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::TimedOut =>
        {
            0
        }
        Err(error) => panic!("test TCP read failed: {error}"),
    };

    stream.set_nonblocking(false).unwrap();
    result
}

fn process_invitation_client_frames(
    session: &mut SptpsHandshakeSession,
    decoder: &mut MetaStreamDecoder,
    stream: &mut TcpStream,
    cookie: &[u8; INVITATION_COOKIE_LEN],
    final_key: &TincEd25519PrivateKey,
    invitation_data: &mut Vec<u8>,
    sent_cookie: &mut bool,
) -> bool {
    let mut accepted = false;

    while let Some(frame) = decoder.next_sptps_frame(session.is_established()).unwrap() {
        let MetaStreamFrame::SptpsRecord(record) = frame else {
            panic!("expected SPTPS record");
        };
        let events = session.receive_datagram(&record).unwrap();

        for record in session.drain_outbound() {
            stream.write_all(&record).unwrap();
            stream.flush().unwrap();
        }

        for event in events {
            match event {
                SptpsHandshakeEvent::HandshakeComplete => {
                    if !*sent_cookie {
                        let record = session.send_record(0, cookie).unwrap();
                        stream.write_all(&record).unwrap();
                        stream.flush().unwrap();
                        *sent_cookie = true;
                    }
                }
                SptpsHandshakeEvent::ApplicationRecord {
                    record_type: 0,
                    payload,
                } => invitation_data.extend(payload),
                SptpsHandshakeEvent::ApplicationRecord {
                    record_type: 1,
                    payload,
                } => {
                    assert!(payload.is_empty());
                    let public_key = final_key.public_key().to_base64();
                    let record = session.send_record(1, public_key.as_bytes()).unwrap();
                    stream.write_all(&record).unwrap();
                    stream.flush().unwrap();
                }
                SptpsHandshakeEvent::ApplicationRecord {
                    record_type: 2,
                    payload,
                } => {
                    assert!(payload.is_empty());
                    accepted = true;
                }
                SptpsHandshakeEvent::ApplicationRecord { record_type, .. } => {
                    panic!("unexpected invitation record type {record_type}");
                }
            }
        }
    }

    accepted
}

fn event_script(label: &str, output: &str) -> String {
    format!(
        "printf '{} NAME=%s NETNAME=%s NODE=%s SUBNET=%s WEIGHT=%s REMOTEADDRESS=%s REMOTEPORT=%s\\n' \"$NAME\" \"$NETNAME\" \"$NODE\" \"$SUBNET\" \"$WEIGHT\" \"$REMOTEADDRESS\" \"$REMOTEPORT\" >> '{}'\n",
        label, output
    )
}

#[cfg(unix)]
fn udp_socket_buffer_size(socket: &UdpSocket, option: libc::c_int) -> io::Result<i32> {
    use std::os::fd::AsRawFd;

    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(unix)]
fn socket_option_i32(fd: i32, level: libc::c_int, option: libc::c_int) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn socket_fwmark(fd: i32) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn socket_bound_device(fd: i32) -> io::Result<String> {
    let mut value = [0u8; LINUX_IFNAMSIZ];
    let mut length = value.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            value.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let length = usize::try_from(length)
        .unwrap_or(value.len())
        .min(value.len());
    let end = value[..length]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length);
    Ok(String::from_utf8_lossy(&value[..end]).into_owned())
}

fn legacy_ans_key_test_daemon(
    alpha_rsa: RsaPrivateKey,
    beta_rsa: &RsaPrivateKey,
) -> RuntimeDaemonState {
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa)),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(beta_rsa))]),
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    alpha.state.graph.ensure_node("beta");
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());
    alpha
}

fn legacy_ans_key_test_message() -> AnswerKeyMessage {
    AnswerKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        key: "42".repeat(48),
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression: 0,
        address: None,
    }
}

fn assert_legacy_ans_key_meta_connection_closes_like_tinc(
    case: &str,
    mutate: impl FnOnce(&mut AnswerKeyMessage),
    message: &str,
) {
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa.clone(), beta_rsa.clone())
    else {
        return;
    };
    let mut alpha = legacy_ans_key_test_daemon(alpha_rsa, &beta_rsa);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);

    let mut bad_answer = legacy_ans_key_test_message();
    mutate(&mut bad_answer);
    let bad_answer = MetaMessage::AnswerKey(bad_answer);
    beta_stream
        .write_all(&beta_driver.send_meta_message(&bad_answer).unwrap())
        .unwrap();

    alpha.poll_once().unwrap();

    assert!(alpha.meta_connections.is_empty(), "{message}");
    assert!(
        !alpha.state.graph.node("beta").unwrap().status.valid_key,
        "C ans_key_h() clears validkey before rejecting {case} legacy ANS_KEY"
    );
}

#[cfg(unix)]
fn assert_systemd_socket_pair_accepts_tcp_and_udp(
    socket: &RuntimeListenSocket,
    address: SocketAddr,
    payload: &[u8; 1],
) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(payload).unwrap();
    let mut accepted = loop {
        match socket.tcp.accept() {
            Ok((accepted, _)) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(5));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    let mut byte = [0u8; 1];
    accepted.set_nonblocking(false).unwrap();
    accepted.read_exact(&mut byte).unwrap();
    assert_eq!(payload, &byte);

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(payload, address).unwrap();
    let mut buffer = [0u8; 1];
    let (len, _) = loop {
        match socket.udp.recv_from(&mut buffer) {
            Ok(result) => break result,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(5));
            }
            Err(error) => panic!("udp recv failed: {error}"),
        }
    };
    assert_eq!(1, len);
    assert_eq!(payload, &buffer);
}

use crate::*;

pub const TINC_CTL_VERSION_CURRENT: i32 = 0;
pub(crate) const REQ_STOP: i32 = 0;
pub(crate) const REQ_RELOAD: i32 = 1;
pub(crate) const REQ_DUMP_NODES: i32 = 3;
pub(crate) const REQ_DUMP_EDGES: i32 = 4;
pub(crate) const REQ_DUMP_SUBNETS: i32 = 5;
pub(crate) const REQ_DUMP_CONNECTIONS: i32 = 6;
pub(crate) const REQ_PURGE: i32 = 8;
pub(crate) const REQ_SET_DEBUG: i32 = 9;
pub(crate) const REQ_RETRY: i32 = 10;
pub(crate) const REQ_DISCONNECT: i32 = 12;
pub(crate) const REQ_DUMP_TRAFFIC: i32 = 13;
pub(crate) const REQ_PCAP: i32 = 14;
pub(crate) const REQ_LOG: i32 = 15;
pub(crate) const DEBUG_UNSET: i32 = -1;
pub(crate) const DEBUG_NOTHING: i32 = 0;
pub(crate) const DEBUG_SCARY_THINGS: i32 = 10;
pub(crate) const LOG_EMERG: i32 = 0;
pub(crate) const LOG_ALERT: i32 = 1;
pub(crate) const LOG_CRIT: i32 = 2;
pub(crate) const LOG_ERR: i32 = 3;
pub(crate) const LOG_WARNING: i32 = 4;
pub(crate) const LOG_NOTICE: i32 = 5;
pub(crate) const LOG_INFO: i32 = 6;
pub(crate) const LOG_DEBUG: i32 = 7;
pub(crate) const LOG_CONTROL_BUFFER_SIZE: usize = 1024;
pub(crate) const PCAP_CONTROL_BUFFER_SIZE: usize = 9018;
pub(crate) const CONTROL_LOG_RING_CAPACITY: usize = 256;
pub(crate) const CONTROL_PCAP_RING_CAPACITY: usize = 256;
pub(crate) const CONTROL_SUBSCRIBER_QUEUE_CAPACITY: usize = 256;
pub(crate) const MAC_SUBNET_AGE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEndpoint {
    pub pidfile: PathBuf,
    pub socket: PathBuf,
    pub cookie: String,
    pub host: String,
    pub port: String,
    pub pid: u32,
}

impl ControlEndpoint {
    pub fn new(options: &TincdOptions) -> Self {
        let pidfile = resolve_pidfile(options);
        let socket = control_socket_path(&pidfile);
        Self {
            pidfile,
            socket,
            cookie: generate_control_cookie(),
            host: "127.0.0.1".to_owned(),
            port: "655".to_owned(),
            pid: std::process::id(),
        }
    }

    pub(crate) fn for_runtime_listeners(&self, listen_sockets: &[RuntimeListenSocket]) -> Self {
        let mut endpoint = self.clone();
        endpoint.pid = std::process::id();

        if let Some(socket) = listen_sockets.first() {
            let (host, port) = control_host_port_from_listen_address(socket.info().address);
            endpoint.host = host;
            endpoint.port = port;
        }

        endpoint
    }

    pub(crate) fn for_tcp_control_listener(
        &self,
        listener: &TcpListener,
    ) -> Result<Self, TincdError> {
        let mut endpoint = self.clone();
        endpoint.pid = std::process::id();
        let address = listener.local_addr().map_err(control_io)?;
        let (host, port) = control_host_port_from_listen_address(address);
        endpoint.host = host;
        endpoint.port = port;
        Ok(endpoint)
    }
}

pub(crate) fn control_host_port_from_listen_address(address: SocketAddr) -> (String, String) {
    let host = match address.ip() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) => Ipv4Addr::LOCALHOST.to_string(),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED) => Ipv6Addr::LOCALHOST.to_string(),
        ip => ip.to_string(),
    };

    (host, address.port().to_string())
}

pub fn resolve_pidfile(options: &TincdOptions) -> PathBuf {
    options
        .pidfile
        .clone()
        .unwrap_or_else(|| resolve_confbase(options).join("pid"))
}

pub(crate) fn resolve_logfile(options: &TincdOptions) -> Option<PathBuf> {
    options.logfile.as_ref().map(|path| {
        path.clone()
            .unwrap_or_else(|| resolve_confbase(options).join("log"))
    })
}

pub fn control_socket_path(pidfile: &Path) -> PathBuf {
    let path = pidfile.to_string_lossy();

    if let Some(prefix) = path.strip_suffix(".pid") {
        PathBuf::from(format!("{prefix}.socket"))
    } else {
        PathBuf::from(format!("{path}.socket"))
    }
}

pub fn write_control_pidfile(endpoint: &ControlEndpoint) -> Result<(), TincdError> {
    if let Some(parent) = endpoint.pidfile.parent() {
        fs::create_dir_all(parent).map_err(control_io)?;
    }

    fs::write(
        &endpoint.pidfile,
        format!(
            "{} {} {} port {}\n",
            endpoint.pid, endpoint.cookie, endpoint.host, endpoint.port
        ),
    )
    .map_err(control_io)
}

pub fn remove_control_files(endpoint: &ControlEndpoint) {
    let _ = fs::remove_file(&endpoint.socket);
    let _ = fs::remove_file(&endpoint.pidfile);
}

pub(crate) const FOREGROUND_IDLE_SLEEP: Duration = Duration::from_millis(50);
pub(crate) const OUTGOING_CONNECT_TIMEOUT: Duration = Duration::from_millis(50);
pub(crate) const AUTOCONNECT_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const DEVICE_DRAIN_BUDGET: usize = 256;
pub(crate) const UDP_DRAIN_BUDGET_PER_SOCKET: usize = 256;
pub(crate) const OUTGOING_CONNECT_RETRY_STEP_SECS: u64 = 5;
pub(crate) const SPTPS_UDP_ROUTER_PACKET_TYPE: u8 = 0;
pub(crate) const SPTPS_UDP_PROBE_TYPE: u8 = 4;
pub(crate) const UDP_PROBE_MIN_SIZE: usize = 18;
pub(crate) const UDP_PROBE_ETHERTYPE_OFFSET: usize = 12;
pub(crate) const PMTU_INITIAL_PROBES: i32 = 20;
pub(crate) const PMTU_PROBES_PER_CYCLE: i32 = 8;
pub(crate) const PMTU_INITIAL_PROBE_INTERVAL: Duration = Duration::from_micros(333_333);
pub(crate) const PMTU_NEGATIVE_PROBE_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const UDP_UNCONFIRMED_LATEST_GUESS_PERIOD: usize = 3;
pub(crate) const INVITATION_LABEL: &[u8] = b"tinc invitation";
pub(crate) const INVITATION_COOKIE_LEN: usize = 18;
pub(crate) const TARPIT_CAPACITY: usize = 10;
pub(crate) const MAX_CACHED_ADDRESSES: usize = 8;
pub(crate) const ADDRESS_CACHE_VERSION: u32 = 1;

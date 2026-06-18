// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::CString;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr};

use tinc_core::config::{Config, ConfigTree, ConfigValueError};
use tinc_core::route::{ForwardingMode, RouteConfig, RoutingMode};
use tinc_core::state::NetworkState;
use tinc_core::subnet::{Subnet, SubnetParseError};
use tinc_core::utils::check_id;

use crate::connection::MetaNetworkMode;
use crate::device::MTU;
use crate::engine::{BroadcastMode, EngineConfig};
use crate::transport::NodeAddressTable;
use crate::transport::{CompressionLevel, LegacyCipherAlgorithm, LegacyDigest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub name: String,
    pub state: NetworkState,
    pub experimental_protocol: Option<bool>,
    pub engine: EngineConfig,
    pub daemon: DaemonConfig,
    pub addresses: NodeAddressTable,
    pub peer_meta_configs: BTreeMap<String, PeerMetaConfig>,
    pub meta_network_mode: MetaNetworkMode,
    pub strict_subnets: bool,
    pub tunnel_server: bool,
    pub autoconnect: bool,
    pub connect_to: Vec<String>,
}

impl RuntimeConfig {
    pub fn from_config_tree(tree: &ConfigTree) -> Result<Self, RuntimeConfigError> {
        Self::from_config_tree_with_hosts(tree, [])
    }

    pub fn from_config_tree_with_hosts<'a>(
        tree: &ConfigTree,
        host_configs: impl IntoIterator<Item = (&'a str, &'a ConfigTree)>,
    ) -> Result<Self, RuntimeConfigError> {
        let name = required_string(tree, "Name")?;

        if !check_id(&name) {
            return Err(RuntimeConfigError::InvalidName(name));
        }

        let mut route = RouteConfig::default();
        route.routing_mode = parse_routing_mode(tree.lookup("Mode"))?;
        route.forwarding_mode = parse_forwarding_mode(tree.lookup("Forwarding"))?;
        route.direct_only = optional_bool(tree.lookup("DirectOnly"))?.unwrap_or(false);
        route.decrement_ttl = optional_bool(tree.lookup("DecrementTTL"))?.unwrap_or(false);
        route.priority_inheritance =
            optional_bool(tree.lookup("PriorityInheritance"))?.unwrap_or(false);

        let broadcast = parse_broadcast_mode(tree.lookup("Broadcast"))?;
        let tunnel_server = optional_bool(tree.lookup("TunnelServer"))?.unwrap_or(false);
        let broadcast = if tunnel_server {
            BroadcastMode::None
        } else {
            broadcast
        };
        let engine = EngineConfig { route, broadcast };
        let daemon = DaemonConfig::from_config_tree(tree)?;

        let strict_subnets =
            optional_bool(tree.lookup("StrictSubnets"))?.unwrap_or(false) || tunnel_server;
        let autoconnect = optional_bool(tree.lookup("AutoConnect"))?.unwrap_or(true);
        let meta_network_mode = if tunnel_server {
            MetaNetworkMode::TunnelServer
        } else {
            MetaNetworkMode::Mesh
        };

        let experimental_protocol = optional_bool(tree.lookup("ExperimentalProtocol"))?;
        let mut state = NetworkState::new(&name);
        state.experimental = experimental_protocol.unwrap_or(true);
        let mut addresses = NodeAddressTable::new();
        let mut peer_meta_configs = BTreeMap::new();

        add_owner_subnets(&mut state, &name, tree, SubnetErrorMode::Strict)?;
        add_broadcast_subnets(&mut state, tree);
        apply_host_configs(
            &mut state,
            &mut addresses,
            &mut peer_meta_configs,
            &name,
            strict_subnets,
            daemon.address_family,
            host_configs,
        );

        if let Some(myself) = state.graph.node_mut(&name) {
            myself.status.reachable = true;
            myself.status.sptps = state.experimental;
            myself.route.next_hop = Some(name.clone());
            myself.route.via = Some(name.clone());
            myself.route.distance = Some(0);
            myself.route.weighted_distance = Some(0);
        }

        Ok(Self {
            name,
            state,
            experimental_protocol,
            engine,
            daemon,
            addresses,
            peer_meta_configs,
            meta_network_mode,
            strict_subnets,
            tunnel_server,
            autoconnect,
            connect_to: tree
                .lookup_all("ConnectTo")
                .map(|config| config.value.clone())
                .collect(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub port: String,
    pub port_specified: bool,
    pub address_family: ListenAddressFamily,
    pub proxy: ProxyConfig,
    pub bind_to_addresses: Vec<ListenAddress>,
    pub listen_addresses: Vec<ListenAddress>,
    pub bind_to_interface: Option<String>,
    pub device: DeviceConfig,
    pub device_standby: bool,
    pub ping_interval: i32,
    pub ping_timeout: i32,
    pub mac_expire: i32,
    pub key_expire: i32,
    pub mtu_info_interval: i32,
    pub udp_info_interval: i32,
    pub local_discovery: bool,
    pub udp_discovery: bool,
    pub udp_discovery_keepalive_interval: i32,
    pub udp_discovery_interval: i32,
    pub udp_discovery_timeout: i32,
    pub upnp: UpnpConfig,
    pub hostnames: bool,
    pub max_timeout: i32,
    pub max_output_buffer_size: usize,
    pub max_connection_burst: i32,
    pub invitation_expire: i32,
    pub udp_rcvbuf: i32,
    pub udp_sndbuf: i32,
    pub fwmark: i32,
    pub log_level: Option<i32>,
    pub process_priority: Option<ProcessPriority>,
    pub sandbox: SandboxLevel,
    pub indirect_data: bool,
    pub tcp_only: bool,
    pub pmtu_discovery: bool,
    pub clamp_mss: bool,
    pub replay_window: Option<usize>,
    pub legacy_cipher: LegacyCipherAlgorithm,
    pub legacy_digest: LegacyDigest,
    pub legacy_compression: CompressionLevel,
    pub weight: Option<i32>,
    pub scripts: ScriptConfig,
}

impl DaemonConfig {
    fn from_config_tree(tree: &ConfigTree) -> Result<Self, RuntimeConfigError> {
        let port_config = tree.lookup("Port");
        let port = port_config
            .map(|config| config.value.clone())
            .unwrap_or_else(|| "655".to_owned());
        let (ping_interval, ping_timeout) = parse_ping_timing(tree)?;

        let legacy_mac_length =
            nonnegative_i32(tree.lookup("MACLength"), "MACLength")?.unwrap_or(4) as usize;

        Ok(Self {
            port: port.clone(),
            port_specified: port_config.is_some(),
            address_family: parse_address_family(tree.lookup("AddressFamily"))?,
            proxy: parse_proxy_config(tree.lookup("Proxy"))?,
            bind_to_addresses: parse_listen_addresses(
                tree.lookup_all("BindToAddress"),
                &port,
                true,
            ),
            listen_addresses: parse_listen_addresses(
                tree.lookup_all("ListenAddress"),
                &port,
                false,
            ),
            bind_to_interface: tree
                .lookup("BindToInterface")
                .map(|config| config.value.clone()),
            device: DeviceConfig::from_config_tree(tree)?,
            device_standby: optional_bool(tree.lookup("DeviceStandby"))?.unwrap_or(false),
            ping_interval,
            ping_timeout,
            mac_expire: optional_i32(tree.lookup("MACExpire"))?.unwrap_or(600),
            key_expire: optional_i32(tree.lookup("KeyExpire"))?.unwrap_or(3600),
            mtu_info_interval: optional_i32(tree.lookup("MTUInfoInterval"))?.unwrap_or(5),
            udp_info_interval: optional_i32(tree.lookup("UDPInfoInterval"))?.unwrap_or(5),
            local_discovery: optional_bool(tree.lookup("LocalDiscovery"))?.unwrap_or(true),
            udp_discovery: optional_bool(tree.lookup("UDPDiscovery"))?.unwrap_or(true),
            udp_discovery_keepalive_interval: optional_i32(
                tree.lookup("UDPDiscoveryKeepaliveInterval"),
            )?
            .unwrap_or(10),
            udp_discovery_interval: optional_i32(tree.lookup("UDPDiscoveryInterval"))?.unwrap_or(2),
            udp_discovery_timeout: optional_i32(tree.lookup("UDPDiscoveryTimeout"))?.unwrap_or(30),
            upnp: UpnpConfig::from_config_tree(tree)?,
            hostnames: optional_bool(tree.lookup("Hostnames"))?.unwrap_or(false),
            max_timeout: positive_i32(tree.lookup("MaxTimeout"), "MaxTimeout")?.unwrap_or(900),
            max_output_buffer_size: nonnegative_i32(
                tree.lookup("MaxOutputBufferSize"),
                "MaxOutputBufferSize",
            )?
            .map(|value| value as usize)
            .unwrap_or(10 * MTU),
            max_connection_burst: positive_i32(
                tree.lookup("MaxConnectionBurst"),
                "MaxConnectionBurst",
            )?
            .unwrap_or(10),
            invitation_expire: optional_i32(tree.lookup("InvitationExpire"))?.unwrap_or(604800),
            udp_rcvbuf: nonnegative_i32(tree.lookup("UDPRcvBuf"), "UDPRcvBuf")?
                .unwrap_or(1024 * 1024),
            udp_sndbuf: nonnegative_i32(tree.lookup("UDPSndBuf"), "UDPSndBuf")?
                .unwrap_or(1024 * 1024),
            fwmark: optional_i32(tree.lookup("FWMark"))?.unwrap_or(0),
            log_level: optional_i32(tree.lookup("LogLevel"))?,
            process_priority: parse_process_priority(tree.lookup("ProcessPriority"))?,
            sandbox: parse_sandbox_level(tree.lookup("Sandbox"))?,
            indirect_data: optional_bool(tree.lookup("IndirectData"))?.unwrap_or(false),
            tcp_only: optional_bool(tree.lookup("TCPOnly"))?.unwrap_or(false),
            pmtu_discovery: optional_bool(tree.lookup("PMTUDiscovery"))?.unwrap_or(true),
            clamp_mss: optional_bool(tree.lookup("ClampMSS"))?.unwrap_or(true),
            replay_window: nonnegative_i32(tree.lookup("ReplayWindow"), "ReplayWindow")?
                .map(|value| value as usize),
            legacy_cipher: parse_legacy_cipher(tree.lookup("Cipher"))?,
            legacy_digest: parse_legacy_digest(tree.lookup("Digest"), legacy_mac_length)?,
            legacy_compression: parse_legacy_compression(tree.lookup("Compression"))?,
            weight: optional_i32(tree.lookup("Weight"))?,
            scripts: ScriptConfig::from_config_tree(tree),
        })
    }

    pub fn effective_listen_addresses(&self) -> Vec<ListenAddress> {
        let mut addresses = Vec::new();
        addresses.extend(self.bind_to_addresses.clone());
        addresses.extend(self.listen_addresses.clone());

        if !addresses.is_empty() {
            return addresses;
        }

        vec![ListenAddress {
            address: None,
            port: self.port.clone(),
            bind_to: false,
        }]
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ListenAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenAddress {
    pub address: Option<String>,
    pub port: String,
    pub bind_to: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptConfig {
    pub interpreter: Option<String>,
    pub extension: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UpnpConfig {
    pub mode: UpnpMode,
    pub discover_wait: i32,
    pub refresh_period: i32,
}

impl UpnpConfig {
    fn from_config_tree(tree: &ConfigTree) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            mode: parse_upnp_mode(tree.lookup("UPnP")),
            discover_wait: optional_i32(tree.lookup("UPnPDiscoverWait"))?.unwrap_or(5),
            refresh_period: optional_i32(tree.lookup("UPnPRefreshPeriod"))?.unwrap_or(60),
        })
    }

    pub const fn maps_tcp(self) -> bool {
        matches!(self.mode, UpnpMode::TcpAndUdp)
    }

    pub const fn maps_udp(self) -> bool {
        matches!(self.mode, UpnpMode::TcpAndUdp | UpnpMode::UdpOnly)
    }

    pub const fn is_enabled(self) -> bool {
        self.maps_tcp() || self.maps_udp()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpnpMode {
    #[default]
    Off,
    TcpAndUdp,
    UdpOnly,
}

impl ScriptConfig {
    fn from_config_tree(tree: &ConfigTree) -> Self {
        Self {
            interpreter: tree
                .lookup("ScriptsInterpreter")
                .map(|config| config.value.clone()),
            extension: tree
                .lookup("ScriptsExtension")
                .map(|config| config.value.clone())
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPriority {
    Low,
    Normal,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SandboxLevel {
    Off,
    Normal,
    High,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyConfig {
    None,
    Http {
        host: String,
        port: String,
        user: Option<String>,
        password: Option<String>,
    },
    Socks4 {
        host: String,
        port: String,
        user: Option<String>,
    },
    Socks4a {
        host: String,
        port: String,
        user: Option<String>,
        password: Option<String>,
    },
    Socks5 {
        host: String,
        port: String,
        user: Option<String>,
        password: Option<String>,
    },
    Exec {
        command: String,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerMetaConfig {
    pub indirect_data: bool,
    pub tcp_only: bool,
    pub clamp_mss: Option<bool>,
    pub weight: Option<i32>,
}

impl PeerMetaConfig {
    fn from_host_tree(tree: &ConfigTree) -> Self {
        Self {
            indirect_data: host_bool(tree, "IndirectData").unwrap_or(false),
            tcp_only: host_bool(tree, "TCPOnly").unwrap_or(false),
            clamp_mss: host_bool(tree, "ClampMSS"),
            weight: host_i32(tree, "Weight"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceConfig {
    pub device_type: DeviceType,
    pub device: Option<String>,
    pub interface: Option<String>,
    pub iff_one_queue: bool,
    pub vde_port: i32,
    pub vde_group: Option<String>,
}

impl DeviceConfig {
    fn from_config_tree(tree: &ConfigTree) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            device_type: tree
                .lookup("DeviceType")
                .map(|config| DeviceType::from_config_value(&config.value))
                .unwrap_or(DeviceType::System),
            device: tree.lookup("Device").map(|config| config.value.clone()),
            interface: tree.lookup("Interface").map(|config| config.value.clone()),
            iff_one_queue: optional_bool(tree.lookup("IffOneQueue"))?.unwrap_or(false),
            vde_port: optional_i32(tree.lookup("VDEPort"))?.unwrap_or(0),
            vde_group: tree.lookup("VDEGroup").map(|config| config.value.clone()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceType {
    System,
    Tun,
    Tap,
    Dummy,
    RawSocket,
    Multicast,
    Fd,
    Uml,
    Vde,
    Other(String),
}

impl DeviceType {
    fn from_config_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("tun") {
            Self::Tun
        } else if value.eq_ignore_ascii_case("tap") {
            Self::Tap
        } else if value.eq_ignore_ascii_case("dummy") {
            Self::Dummy
        } else if value.eq_ignore_ascii_case("raw_socket") {
            Self::RawSocket
        } else if value.eq_ignore_ascii_case("multicast") {
            Self::Multicast
        } else if value.eq_ignore_ascii_case("fd") {
            Self::Fd
        } else if value.eq_ignore_ascii_case("uml") {
            Self::Uml
        } else if value.eq_ignore_ascii_case("vde") {
            Self::Vde
        } else {
            Self::Other(value.to_owned())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeConfigError {
    MissingRequired {
        variable: &'static str,
    },
    InvalidName(String),
    Bool(ConfigValueError),
    InvalidRoutingMode(String),
    InvalidForwardingMode(String),
    InvalidBroadcastMode(String),
    InvalidAddressFamily(String),
    InvalidLegacyCipher(String),
    InvalidLegacyDigest(String),
    InvalidLegacyCompression(i32),
    InvalidProcessPriority(String),
    InvalidSandboxLevel(String),
    UnsupportedSandboxLevel(SandboxLevel),
    InvalidProxy(String),
    UnsupportedProxy(String),
    NegativeInteger {
        variable: &'static str,
        value: i32,
    },
    NonPositiveInteger {
        variable: &'static str,
        value: i32,
    },
    Subnet {
        variable: String,
        value: String,
        error: SubnetParseError,
    },
    SubnetMask {
        variable: String,
        value: String,
    },
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequired { variable } => {
                write!(f, "missing required configuration variable {variable}")
            }
            Self::InvalidName(name) => write!(f, "invalid tinc node name {name}"),
            Self::Bool(error) => write!(f, "{error}"),
            Self::InvalidRoutingMode(value) => write!(f, "invalid routing mode {value}"),
            Self::InvalidForwardingMode(value) => write!(f, "invalid forwarding mode {value}"),
            Self::InvalidBroadcastMode(value) => write!(f, "invalid broadcast mode {value}"),
            Self::InvalidAddressFamily(value) => write!(f, "invalid address family {value}"),
            Self::InvalidLegacyCipher(value) => write!(f, "invalid legacy cipher {value}"),
            Self::InvalidLegacyDigest(value) => write!(f, "invalid legacy digest {value}"),
            Self::InvalidLegacyCompression(value) => {
                write!(f, "invalid legacy compression level {value}")
            }
            Self::InvalidProcessPriority(value) => write!(f, "invalid process priority {value}"),
            Self::InvalidSandboxLevel(value) => write!(f, "invalid sandbox level {value}"),
            Self::UnsupportedSandboxLevel(level) => {
                write!(
                    f,
                    "sandbox level {level:?} is not supported on this platform"
                )
            }
            Self::InvalidProxy(value) => write!(f, "invalid proxy configuration {value}"),
            Self::UnsupportedProxy(value) => write!(f, "proxy type {value} is not supported"),
            Self::NegativeInteger { variable, value } => {
                write!(f, "{variable} cannot be negative: {value}")
            }
            Self::NonPositiveInteger { variable, value } => {
                write!(f, "{variable} must be positive: {value}")
            }
            Self::Subnet {
                variable,
                value,
                error,
            } => {
                write!(
                    f,
                    "subnet expected for configuration variable {variable} value {value}: {error}"
                )
            }
            Self::SubnetMask { variable, value } => {
                write!(
                    f,
                    "network address and prefix length do not match for configuration variable {variable} value {value}"
                )
            }
        }
    }
}

impl std::error::Error for RuntimeConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bool(error) => Some(error),
            Self::Subnet { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<ConfigValueError> for RuntimeConfigError {
    fn from(error: ConfigValueError) -> Self {
        Self::Bool(error)
    }
}

fn apply_host_configs<'a>(
    state: &mut NetworkState,
    addresses: &mut NodeAddressTable,
    peer_meta_configs: &mut BTreeMap<String, PeerMetaConfig>,
    myself: &str,
    strict_subnets: bool,
    address_family: ListenAddressFamily,
    host_configs: impl IntoIterator<Item = (&'a str, &'a ConfigTree)>,
) {
    for (host, tree) in host_configs {
        if host == myself {
            continue;
        }

        state.graph.ensure_node(host);

        if tree.lookup("Address").is_some()
            && let Some(node) = state.graph.node_mut(host)
        {
            node.status.has_address = true;
        }

        add_node_addresses(addresses, host, tree, address_family);
        let peer_meta = PeerMetaConfig::from_host_tree(tree);
        if peer_meta != PeerMetaConfig::default() {
            peer_meta_configs.insert(host.to_owned(), peer_meta);
        }

        if strict_subnets {
            let _ = add_owner_subnets(state, host, tree, SubnetErrorMode::IgnoreInvalid);
        }
    }
}

fn add_node_addresses(
    addresses: &mut NodeAddressTable,
    host: &str,
    tree: &ConfigTree,
    address_family: ListenAddressFamily,
) {
    for config in tree.lookup_all("Address") {
        for address in parse_address_config(config, tree, address_family) {
            addresses.push(host, address);
        }
    }
}

fn parse_address_config(
    config: &Config,
    tree: &ConfigTree,
    address_family: ListenAddressFamily,
) -> Vec<SocketAddr> {
    let mut parts = config.value.split_whitespace();
    let Some(host) = parts.next() else {
        return Vec::new();
    };
    let port = parts
        .next()
        .map(str::to_owned)
        .or_else(|| tree.lookup("Port").map(|config| config.value.clone()))
        .unwrap_or_else(|| "655".to_owned());

    resolve_config_socket_addresses(host, &port, address_family)
}

fn resolve_config_socket_addresses(
    host: &str,
    service: &str,
    address_family: ListenAddressFamily,
) -> Vec<SocketAddr> {
    if let Ok(port) = service.parse::<u16>() {
        return (host, port)
            .to_socket_addrs()
            .map(|addresses| {
                addresses
                    .filter(|address| address_matches_family(*address, address_family))
                    .collect()
            })
            .unwrap_or_default();
    }

    resolve_service_socket_addresses(host, service, address_family)
}

#[cfg(unix)]
fn resolve_service_socket_addresses(
    host: &str,
    service: &str,
    address_family: ListenAddressFamily,
) -> Vec<SocketAddr> {
    let Ok(host) = CString::new(host) else {
        return Vec::new();
    };
    let Ok(service) = CString::new(service) else {
        return Vec::new();
    };
    let mut hints = unsafe { std::mem::zeroed::<libc::addrinfo>() };
    hints.ai_family = libc_address_family(address_family);
    hints.ai_socktype = libc::SOCK_STREAM;

    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    let error = unsafe {
        libc::getaddrinfo(
            host.as_ptr(),
            service.as_ptr(),
            &hints,
            &mut result as *mut *mut libc::addrinfo,
        )
    };

    if error != 0 || result.is_null() {
        return Vec::new();
    }

    let mut addresses = Vec::new();
    let mut current = result;
    while !current.is_null() {
        if let Some(address) = unsafe { socket_addr_from_raw((*current).ai_addr) }
            && address_matches_family(address, address_family)
        {
            addresses.push(address);
        }
        current = unsafe { (*current).ai_next };
    }

    unsafe {
        libc::freeaddrinfo(result);
    }

    addresses
}

#[cfg(not(unix))]
fn resolve_service_socket_addresses(
    _host: &str,
    _service: &str,
    _address_family: ListenAddressFamily,
) -> Vec<SocketAddr> {
    Vec::new()
}

#[cfg(unix)]
fn libc_address_family(address_family: ListenAddressFamily) -> libc::c_int {
    match address_family {
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

fn address_matches_family(address: SocketAddr, family: ListenAddressFamily) -> bool {
    matches!(
        (address.ip(), family),
        (_, ListenAddressFamily::Any)
            | (IpAddr::V4(_), ListenAddressFamily::Ipv4)
            | (IpAddr::V6(_), ListenAddressFamily::Ipv6)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubnetErrorMode {
    Strict,
    IgnoreInvalid,
}

const DEFAULT_BROADCAST_SUBNETS: &[&str] = &[
    "ff:ff:ff:ff:ff:ff",
    "255.255.255.255",
    "224.0.0.0/4",
    "ff00::/8",
];

fn add_broadcast_subnets(state: &mut NetworkState, tree: &ConfigTree) {
    for value in DEFAULT_BROADCAST_SUBNETS {
        let subnet = value
            .parse::<Subnet>()
            .expect("default broadcast subnet is valid");
        state.subnets.add(subnet);
    }

    for config in tree.lookup_all("BroadcastSubnet") {
        if let Ok(subnet) = parse_config_subnet(config) {
            state.subnets.add(subnet);
        }
    }
}

fn add_owner_subnets(
    state: &mut NetworkState,
    owner: &str,
    tree: &ConfigTree,
    error_mode: SubnetErrorMode,
) -> Result<(), RuntimeConfigError> {
    for config in tree.lookup_all("Subnet") {
        let subnet = match parse_config_subnet(config) {
            Ok(subnet) => subnet,
            Err(_) if error_mode == SubnetErrorMode::IgnoreInvalid => continue,
            Err(error) => return Err(error),
        };

        state
            .subnets
            .add_unique(subnet.with_owner(owner.to_owned()));
    }

    Ok(())
}

fn parse_config_subnet(config: &Config) -> Result<Subnet, RuntimeConfigError> {
    let subnet = config
        .value
        .parse::<Subnet>()
        .map_err(|error| RuntimeConfigError::Subnet {
            variable: config.variable.clone(),
            value: config.value.clone(),
            error,
        })?;

    if !subnet.has_canonical_mask() {
        return Err(RuntimeConfigError::SubnetMask {
            variable: config.variable.clone(),
            value: config.value.clone(),
        });
    }

    Ok(subnet)
}

fn required_string(
    tree: &ConfigTree,
    variable: &'static str,
) -> Result<String, RuntimeConfigError> {
    tree.lookup(variable)
        .map(|config| config.value.clone())
        .ok_or(RuntimeConfigError::MissingRequired { variable })
}

fn optional_bool(config: Option<&Config>) -> Result<Option<bool>, RuntimeConfigError> {
    config.map(Config::as_bool).transpose().map_err(Into::into)
}

fn optional_i32(config: Option<&Config>) -> Result<Option<i32>, RuntimeConfigError> {
    config.map(Config::as_i32).transpose().map_err(Into::into)
}

fn parse_ping_timing(tree: &ConfigTree) -> Result<(i32, i32), RuntimeConfigError> {
    let mut ping_interval = optional_i32(tree.lookup("PingInterval"))?.unwrap_or(60);
    if ping_interval < 1 {
        ping_interval = 86400;
    }

    let mut ping_timeout = optional_i32(tree.lookup("PingTimeout"))?.unwrap_or(5);
    if ping_timeout < 1 || ping_timeout > ping_interval {
        ping_timeout = ping_interval;
    }

    Ok((ping_interval, ping_timeout))
}

fn host_bool(tree: &ConfigTree, variable: &str) -> Option<bool> {
    optional_bool(tree.lookup(variable)).ok().flatten()
}

fn host_i32(tree: &ConfigTree, variable: &str) -> Option<i32> {
    optional_i32(tree.lookup(variable)).ok().flatten()
}

fn nonnegative_i32(
    config: Option<&Config>,
    variable: &'static str,
) -> Result<Option<i32>, RuntimeConfigError> {
    let value = optional_i32(config)?;
    if let Some(value) = value
        && value < 0
    {
        return Err(RuntimeConfigError::NegativeInteger { variable, value });
    }
    Ok(value)
}

fn positive_i32(
    config: Option<&Config>,
    variable: &'static str,
) -> Result<Option<i32>, RuntimeConfigError> {
    let value = optional_i32(config)?;
    if let Some(value) = value
        && value <= 0
    {
        return Err(RuntimeConfigError::NonPositiveInteger { variable, value });
    }
    Ok(value)
}

fn parse_address_family(
    config: Option<&Config>,
) -> Result<ListenAddressFamily, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(ListenAddressFamily::Any);
    };

    if config.value.eq_ignore_ascii_case("any") {
        Ok(ListenAddressFamily::Any)
    } else if config.value.eq_ignore_ascii_case("ipv4") {
        Ok(ListenAddressFamily::Ipv4)
    } else if config.value.eq_ignore_ascii_case("ipv6") {
        Ok(ListenAddressFamily::Ipv6)
    } else {
        Err(RuntimeConfigError::InvalidAddressFamily(
            config.value.clone(),
        ))
    }
}

fn parse_upnp_mode(config: Option<&Config>) -> UpnpMode {
    let Some(config) = config else {
        return UpnpMode::Off;
    };

    if config.value.eq_ignore_ascii_case("yes") {
        UpnpMode::TcpAndUdp
    } else if config.value.eq_ignore_ascii_case("udponly") {
        UpnpMode::UdpOnly
    } else {
        UpnpMode::Off
    }
}

fn parse_legacy_cipher(
    config: Option<&Config>,
) -> Result<LegacyCipherAlgorithm, RuntimeConfigError> {
    let value = config
        .map(|config| config.value.as_str())
        .unwrap_or("aes-256-cbc");

    LegacyCipherAlgorithm::from_name(value)
        .ok_or_else(|| RuntimeConfigError::InvalidLegacyCipher(value.to_owned()))
}

fn parse_legacy_digest(
    config: Option<&Config>,
    mac_length: usize,
) -> Result<LegacyDigest, RuntimeConfigError> {
    let value = config
        .map(|config| config.value.as_str())
        .unwrap_or("sha256");

    LegacyDigest::from_name_and_length(value, mac_length)
        .ok_or_else(|| RuntimeConfigError::InvalidLegacyDigest(value.to_owned()))
}

fn parse_legacy_compression(
    config: Option<&Config>,
) -> Result<CompressionLevel, RuntimeConfigError> {
    match optional_i32(config)?.unwrap_or(0) {
        0 => Ok(CompressionLevel::None),
        1 => Ok(CompressionLevel::Zlib1),
        2 => Ok(CompressionLevel::Zlib2),
        3 => Ok(CompressionLevel::Zlib3),
        4 => Ok(CompressionLevel::Zlib4),
        5 => Ok(CompressionLevel::Zlib5),
        6 => Ok(CompressionLevel::Zlib6),
        7 => Ok(CompressionLevel::Zlib7),
        8 => Ok(CompressionLevel::Zlib8),
        9 => Ok(CompressionLevel::Zlib9),
        10 => Ok(CompressionLevel::LzoLow),
        11 => Ok(CompressionLevel::LzoHigh),
        12 => Ok(CompressionLevel::Lz4),
        value => Err(RuntimeConfigError::InvalidLegacyCompression(value)),
    }
}

fn parse_listen_addresses<'a>(
    configs: impl Iterator<Item = &'a Config>,
    default_port: &str,
    bind_to: bool,
) -> Vec<ListenAddress> {
    configs
        .map(|config| parse_listen_address(&config.value, default_port, bind_to))
        .collect()
}

fn parse_listen_address(value: &str, default_port: &str, bind_to: bool) -> ListenAddress {
    let split = value.find(char::is_whitespace);
    let (address, port) = split
        .map(|index| (&value[..index], value[index..].trim_start()))
        .unwrap_or((value, default_port));
    let address = if address == "*" || address.is_empty() {
        None
    } else {
        Some(address.to_owned())
    };
    let port = if port.is_empty() {
        default_port.to_owned()
    } else {
        port.to_owned()
    };

    ListenAddress {
        address,
        port,
        bind_to,
    }
}

fn parse_routing_mode(config: Option<&Config>) -> Result<RoutingMode, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(RouteConfig::default().routing_mode);
    };

    if config.value.eq_ignore_ascii_case("router") {
        Ok(RoutingMode::Router)
    } else if config.value.eq_ignore_ascii_case("switch") {
        Ok(RoutingMode::Switch)
    } else if config.value.eq_ignore_ascii_case("hub") {
        Ok(RoutingMode::Hub)
    } else {
        Err(RuntimeConfigError::InvalidRoutingMode(config.value.clone()))
    }
}

fn parse_forwarding_mode(config: Option<&Config>) -> Result<ForwardingMode, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(RouteConfig::default().forwarding_mode);
    };

    if config.value.eq_ignore_ascii_case("off") {
        Ok(ForwardingMode::Off)
    } else if config.value.eq_ignore_ascii_case("internal") {
        Ok(ForwardingMode::Internal)
    } else if config.value.eq_ignore_ascii_case("kernel") {
        Ok(ForwardingMode::Kernel)
    } else {
        Err(RuntimeConfigError::InvalidForwardingMode(
            config.value.clone(),
        ))
    }
}

fn parse_broadcast_mode(config: Option<&Config>) -> Result<BroadcastMode, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(EngineConfig::default().broadcast);
    };

    if config.value.eq_ignore_ascii_case("no") {
        Ok(BroadcastMode::None)
    } else if config.value.eq_ignore_ascii_case("yes") || config.value.eq_ignore_ascii_case("mst") {
        Ok(BroadcastMode::Mst)
    } else if config.value.eq_ignore_ascii_case("direct") {
        Ok(BroadcastMode::Direct)
    } else {
        Err(RuntimeConfigError::InvalidBroadcastMode(
            config.value.clone(),
        ))
    }
}

fn parse_process_priority(
    config: Option<&Config>,
) -> Result<Option<ProcessPriority>, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(None);
    };

    if config.value.eq_ignore_ascii_case("low") {
        Ok(Some(ProcessPriority::Low))
    } else if config.value.eq_ignore_ascii_case("normal") {
        Ok(Some(ProcessPriority::Normal))
    } else if config.value.eq_ignore_ascii_case("high") {
        Ok(Some(ProcessPriority::High))
    } else {
        Err(RuntimeConfigError::InvalidProcessPriority(
            config.value.clone(),
        ))
    }
}

pub fn default_sandbox_level() -> SandboxLevel {
    if sandbox_supported() {
        SandboxLevel::Normal
    } else {
        SandboxLevel::Off
    }
}

pub const fn sandbox_supported() -> bool {
    cfg!(target_os = "openbsd")
}

fn parse_sandbox_level(config: Option<&Config>) -> Result<SandboxLevel, RuntimeConfigError> {
    let level = parse_sandbox_level_value(config)?;

    if level > SandboxLevel::Off && !sandbox_supported() {
        return Err(RuntimeConfigError::UnsupportedSandboxLevel(level));
    }

    Ok(level)
}

fn parse_sandbox_level_value(config: Option<&Config>) -> Result<SandboxLevel, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(default_sandbox_level());
    };

    if config.value.eq_ignore_ascii_case("off") {
        Ok(SandboxLevel::Off)
    } else if config.value.eq_ignore_ascii_case("normal") {
        Ok(SandboxLevel::Normal)
    } else if config.value.eq_ignore_ascii_case("high") {
        Ok(SandboxLevel::High)
    } else {
        Err(RuntimeConfigError::InvalidSandboxLevel(
            config.value.clone(),
        ))
    }
}

fn parse_proxy_config(config: Option<&Config>) -> Result<ProxyConfig, RuntimeConfigError> {
    let Some(config) = config else {
        return Ok(ProxyConfig::None);
    };

    let fields = config.value.split_whitespace().collect::<Vec<_>>();
    let Some(proxy_type) = fields.first() else {
        return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
    };

    if proxy_type.eq_ignore_ascii_case("none") {
        return Ok(ProxyConfig::None);
    }

    if proxy_type.eq_ignore_ascii_case("http") {
        if fields.len() < 3 {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        }
        return Ok(ProxyConfig::Http {
            host: fields[1].to_owned(),
            port: fields[2].to_owned(),
            user: fields
                .get(3)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
            password: fields
                .get(4)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
        });
    }

    if proxy_type.eq_ignore_ascii_case("socks4") {
        if fields.len() < 3 {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        }
        return Ok(ProxyConfig::Socks4 {
            host: fields[1].to_owned(),
            port: fields[2].to_owned(),
            user: fields
                .get(3)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
        });
    }

    if proxy_type.eq_ignore_ascii_case("socks4a") {
        if fields.len() < 3 {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        }
        return Ok(ProxyConfig::Socks4a {
            host: fields[1].to_owned(),
            port: fields[2].to_owned(),
            user: fields
                .get(3)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
            password: fields
                .get(4)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
        });
    }

    if proxy_type.eq_ignore_ascii_case("socks5") {
        if fields.len() < 3 {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        }
        return Ok(ProxyConfig::Socks5 {
            host: fields[1].to_owned(),
            port: fields[2].to_owned(),
            user: fields
                .get(3)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
            password: fields
                .get(4)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_owned()),
        });
    }

    if proxy_type.eq_ignore_ascii_case("exec") {
        let Some((_, command)) = config.value.split_once(char::is_whitespace) else {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        };
        let command = command.trim_start();
        if command.is_empty() {
            return Err(RuntimeConfigError::InvalidProxy(config.value.clone()));
        }
        return Ok(ProxyConfig::Exec {
            command: command.to_owned(),
        });
    }

    Err(RuntimeConfigError::InvalidProxy(proxy_type.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tinc_core::config::ConfigSource;
    use tinc_core::subnet::MacAddr;

    fn tree(configs: &[(&str, &str)]) -> ConfigTree {
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

    #[test]
    fn runtime_config_uses_tinc_defaults_and_loads_local_subnets() {
        tinc_test_support::assert_can_create_netns();
        let tree = tree(&[
            ("Name", "alpha"),
            ("Subnet", "10.0.0.0/8"),
            ("Subnet", "2001:db8::/32"),
            ("BroadcastSubnet", "10.42.255.255"),
            ("ConnectTo", "beta"),
        ]);

        let config = RuntimeConfig::from_config_tree(&tree).unwrap();

        assert_eq!("alpha", config.name);
        assert_eq!(RoutingMode::Router, config.engine.route.routing_mode);
        assert_eq!(
            ForwardingMode::Internal,
            config.engine.route.forwarding_mode
        );
        assert!(!config.engine.route.priority_inheritance);
        assert_eq!(BroadcastMode::Mst, config.engine.broadcast);
        assert_eq!("655", config.daemon.port);
        assert!(!config.daemon.port_specified);
        assert_eq!(ListenAddressFamily::Any, config.daemon.address_family);
        assert_eq!(
            vec![ListenAddress {
                address: None,
                port: "655".to_owned(),
                bind_to: false,
            }],
            config.daemon.effective_listen_addresses()
        );
        assert_eq!(DeviceType::System, config.daemon.device.device_type);
        assert!(!config.daemon.device.iff_one_queue);
        assert!(!config.daemon.device_standby);
        assert_eq!(60, config.daemon.ping_interval);
        assert_eq!(5, config.daemon.ping_timeout);
        assert_eq!(600, config.daemon.mac_expire);
        assert_eq!(3600, config.daemon.key_expire);
        assert_eq!(5, config.daemon.mtu_info_interval);
        assert_eq!(5, config.daemon.udp_info_interval);
        assert!(config.daemon.local_discovery);
        assert!(config.daemon.udp_discovery);
        assert_eq!(10, config.daemon.udp_discovery_keepalive_interval);
        assert_eq!(2, config.daemon.udp_discovery_interval);
        assert_eq!(30, config.daemon.udp_discovery_timeout);
        assert_eq!(900, config.daemon.max_timeout);
        assert_eq!(10, config.daemon.max_connection_burst);
        assert_eq!(604800, config.daemon.invitation_expire);
        assert_eq!(1024 * 1024, config.daemon.udp_rcvbuf);
        assert_eq!(1024 * 1024, config.daemon.udp_sndbuf);
        assert_eq!(0, config.daemon.fwmark);
        assert_eq!(None, config.daemon.log_level);
        assert_eq!(None, config.daemon.process_priority);
        assert_eq!(SandboxLevel::Off, config.daemon.sandbox);
        assert!(!config.daemon.indirect_data);
        assert!(!config.daemon.tcp_only);
        assert!(config.daemon.pmtu_discovery);
        assert!(config.daemon.clamp_mss);
        assert_eq!(None, config.daemon.replay_window);
        assert_eq!(
            LegacyCipherAlgorithm::Aes256Cbc,
            config.daemon.legacy_cipher
        );
        assert_eq!(
            LegacyDigest::Sha256 { length: 4 },
            config.daemon.legacy_digest
        );
        assert_eq!(CompressionLevel::None, config.daemon.legacy_compression);
        assert_eq!(None, config.daemon.weight);
        assert_eq!(None, config.daemon.scripts.interpreter);
        assert_eq!("", config.daemon.scripts.extension);
        assert_eq!(MetaNetworkMode::Mesh, config.meta_network_mode);
        assert!(!config.strict_subnets);
        assert!(!config.tunnel_server);
        assert!(config.autoconnect);
        assert_eq!(vec!["beta"], config.connect_to);
        assert_eq!(
            Some(0),
            config.state.graph.node("alpha").unwrap().route.distance
        );
        assert_eq!(
            vec!["10.0.0.0/8", "2001:db8::/32"],
            config
                .state
                .subnets
                .owner_subnets("alpha")
                .map(|subnet| subnet.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            None,
            config
                .state
                .subnets
                .lookup_mac(MacAddr::new([0xff; 6]))
                .unwrap()
                .owner
                .as_deref()
        );
        assert_eq!(
            None,
            config
                .state
                .subnets
                .lookup_ipv4(Ipv4Addr::new(255, 255, 255, 255))
                .unwrap()
                .owner
                .as_deref()
        );
        assert_eq!(
            None,
            config
                .state
                .subnets
                .lookup_ipv4(Ipv4Addr::new(224, 1, 2, 3))
                .unwrap()
                .owner
                .as_deref()
        );
        assert_eq!(
            None,
            config
                .state
                .subnets
                .lookup_ipv4(Ipv4Addr::new(10, 42, 255, 255))
                .unwrap()
                .owner
                .as_deref()
        );
        assert_eq!(
            None,
            config
                .state
                .subnets
                .lookup_ipv6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1))
                .unwrap()
                .owner
                .as_deref()
        );
    }

    #[test]
    fn daemon_config_parses_listen_device_and_timing_options() {
        tinc_test_support::assert_can_create_netns();
        let tree = tree(&[
            ("Name", "alpha"),
            ("Port", "8443"),
            ("AddressFamily", "IPv6"),
            ("BindToAddress", "* 9000"),
            ("BindToAddress", "2001:db8::1 9443"),
            ("ListenAddress", "198.51.100.1 655"),
            ("BindToInterface", "eth0"),
            ("DeviceType", "fd"),
            ("Device", "/dev/tap0"),
            ("Interface", "vpn0"),
            ("IffOneQueue", "yes"),
            ("VDEPort", "7"),
            ("VDEGroup", "switchers"),
            ("DeviceStandby", "yes"),
            ("PingInterval", "30"),
            ("PingTimeout", "7"),
            ("MACExpire", "123"),
            ("KeyExpire", "321"),
            ("MTUInfoInterval", "13"),
            ("UDPInfoInterval", "17"),
            ("LocalDiscovery", "no"),
            ("UDPDiscovery", "no"),
            ("UDPDiscoveryKeepaliveInterval", "19"),
            ("UDPDiscoveryInterval", "23"),
            ("UDPDiscoveryTimeout", "29"),
            ("UPnP", "yes"),
            ("UPnPDiscoverWait", "31"),
            ("UPnPRefreshPeriod", "37"),
            ("MaxTimeout", "44"),
            ("MaxOutputBufferSize", "2048"),
            ("MaxConnectionBurst", "12"),
            ("InvitationExpire", "456"),
            ("UDPRcvBuf", "4096"),
            ("UDPSndBuf", "8192"),
            ("FWMark", "7"),
            ("LogLevel", "3"),
            ("ProcessPriority", "High"),
            ("Sandbox", "off"),
            ("IndirectData", "yes"),
            ("TCPOnly", "yes"),
            ("PMTUDiscovery", "no"),
            ("ClampMSS", "no"),
            ("ReplayWindow", "7"),
            ("Weight", "42"),
            ("ScriptsInterpreter", "/bin/sh"),
            ("ScriptsExtension", ".sh"),
        ]);

        let config = RuntimeConfig::from_config_tree(&tree).unwrap();

        assert_eq!("8443", config.daemon.port);
        assert!(config.daemon.port_specified);
        assert_eq!(ListenAddressFamily::Ipv6, config.daemon.address_family);
        assert_eq!(Some("eth0".to_owned()), config.daemon.bind_to_interface);
        assert_eq!(DeviceType::Fd, config.daemon.device.device_type);
        assert_eq!(Some("/dev/tap0".to_owned()), config.daemon.device.device);
        assert_eq!(Some("vpn0".to_owned()), config.daemon.device.interface);
        assert!(config.daemon.device.iff_one_queue);
        assert_eq!(7, config.daemon.device.vde_port);
        assert_eq!(Some("switchers".to_owned()), config.daemon.device.vde_group);
        assert!(config.daemon.device_standby);
        assert_eq!(30, config.daemon.ping_interval);
        assert_eq!(7, config.daemon.ping_timeout);
        assert_eq!(123, config.daemon.mac_expire);
        assert_eq!(321, config.daemon.key_expire);
        assert_eq!(13, config.daemon.mtu_info_interval);
        assert_eq!(17, config.daemon.udp_info_interval);
        assert!(!config.daemon.local_discovery);
        assert!(!config.daemon.udp_discovery);
        assert_eq!(19, config.daemon.udp_discovery_keepalive_interval);
        assert_eq!(23, config.daemon.udp_discovery_interval);
        assert_eq!(29, config.daemon.udp_discovery_timeout);
        assert_eq!(UpnpMode::TcpAndUdp, config.daemon.upnp.mode);
        assert_eq!(31, config.daemon.upnp.discover_wait);
        assert_eq!(37, config.daemon.upnp.refresh_period);
        assert_eq!(44, config.daemon.max_timeout);
        assert_eq!(2048, config.daemon.max_output_buffer_size);
        assert_eq!(12, config.daemon.max_connection_burst);
        assert_eq!(456, config.daemon.invitation_expire);
        assert_eq!(4096, config.daemon.udp_rcvbuf);
        assert_eq!(8192, config.daemon.udp_sndbuf);
        assert_eq!(7, config.daemon.fwmark);
        assert_eq!(Some(3), config.daemon.log_level);
        assert_eq!(Some(ProcessPriority::High), config.daemon.process_priority);
        assert_eq!(SandboxLevel::Off, config.daemon.sandbox);
        assert!(config.daemon.indirect_data);
        assert!(config.daemon.tcp_only);
        assert!(!config.daemon.pmtu_discovery);
        assert!(!config.daemon.clamp_mss);
        assert_eq!(Some(7), config.daemon.replay_window);
        assert_eq!(Some(42), config.daemon.weight);
        assert_eq!(
            Some("/bin/sh".to_owned()),
            config.daemon.scripts.interpreter
        );
        assert_eq!(".sh", config.daemon.scripts.extension);
        assert_eq!(
            vec![
                ListenAddress {
                    address: None,
                    port: "9000".to_owned(),
                    bind_to: true,
                },
                ListenAddress {
                    address: Some("2001:db8::1".to_owned()),
                    port: "9443".to_owned(),
                    bind_to: true,
                },
                ListenAddress {
                    address: Some("198.51.100.1".to_owned()),
                    port: "655".to_owned(),
                    bind_to: false,
                }
            ],
            config.daemon.effective_listen_addresses()
        );
    }

    #[test]
    fn daemon_config_uses_listen_addresses_when_no_bind_to_addresses_exist() {
        tinc_test_support::assert_can_create_netns();
        let tree = tree(&[
            ("Name", "alpha"),
            ("Port", "7000"),
            ("ListenAddress", "192.0.2.10"),
            ("ListenAddress", "* 7001"),
            ("DeviceType", "custom_backend"),
        ]);

        let config = RuntimeConfig::from_config_tree(&tree).unwrap();

        assert_eq!(
            vec![
                ListenAddress {
                    address: Some("192.0.2.10".to_owned()),
                    port: "7000".to_owned(),
                    bind_to: false,
                },
                ListenAddress {
                    address: None,
                    port: "7001".to_owned(),
                    bind_to: false,
                }
            ],
            config.daemon.effective_listen_addresses()
        );
        assert_eq!(
            DeviceType::Other("custom_backend".to_owned()),
            config.daemon.device.device_type
        );
    }

    #[test]
    fn daemon_config_normalizes_ping_timing_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let invalid_interval =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("PingInterval", "0")]))
                .unwrap();
        assert_eq!(86400, invalid_interval.daemon.ping_interval);
        assert_eq!(5, invalid_interval.daemon.ping_timeout);

        let timeout_too_large = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("PingInterval", "30"),
            ("PingTimeout", "31"),
        ]))
        .unwrap();
        assert_eq!(30, timeout_too_large.daemon.ping_interval);
        assert_eq!(30, timeout_too_large.daemon.ping_timeout);

        let timeout_too_small = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("PingInterval", "30"),
            ("PingTimeout", "0"),
        ]))
        .unwrap();
        assert_eq!(30, timeout_too_small.daemon.ping_interval);
        assert_eq!(30, timeout_too_small.daemon.ping_timeout);
    }

    #[test]
    fn daemon_config_defaults_max_output_buffer_size_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let config = RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha")])).unwrap();

        assert_eq!(10 * MTU, config.daemon.max_output_buffer_size);
    }

    #[test]
    fn daemon_config_parses_legacy_udp_crypto_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let config = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("Cipher", "aes-128-cbc"),
            ("Digest", "sha512"),
            ("MACLength", "8"),
            ("Compression", "9"),
        ]))
        .unwrap();

        assert_eq!(
            LegacyCipherAlgorithm::Aes128Cbc,
            config.daemon.legacy_cipher
        );
        assert_eq!(
            LegacyDigest::Sha512 { length: 8 },
            config.daemon.legacy_digest
        );
        assert_eq!(CompressionLevel::Zlib9, config.daemon.legacy_compression);

        let lzo_low =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Compression", "10")]))
                .unwrap();
        assert_eq!(CompressionLevel::LzoLow, lzo_low.daemon.legacy_compression);

        let lzo_high =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Compression", "11")]))
                .unwrap();
        assert_eq!(
            CompressionLevel::LzoHigh,
            lzo_high.daemon.legacy_compression
        );

        let no_crypto = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("Cipher", "none"),
            ("Digest", "none"),
            ("Compression", "12"),
        ]))
        .unwrap();
        assert_eq!(LegacyCipherAlgorithm::None, no_crypto.daemon.legacy_cipher);
        assert_eq!(LegacyDigest::None, no_crypto.daemon.legacy_digest);
        assert_eq!(CompressionLevel::Lz4, no_crypto.daemon.legacy_compression);

        let openssl_crypto = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("Cipher", "DES-EDE3-CBC"),
            ("Digest", "MD5"),
            ("MACLength", "99"),
        ]));
        #[cfg(feature = "openssl-legacy")]
        {
            let openssl_crypto = openssl_crypto.unwrap();
            assert_eq!(
                LegacyCipherAlgorithm::from_name("DES-EDE3-CBC").unwrap(),
                openssl_crypto.daemon.legacy_cipher
            );
            assert_eq!(
                LegacyDigest::from_name_and_length("MD5", usize::MAX).unwrap(),
                openssl_crypto.daemon.legacy_digest
            );
        }
        #[cfg(not(feature = "openssl-legacy"))]
        assert!(matches!(
            openssl_crypto,
            Err(RuntimeConfigError::InvalidLegacyCipher(_))
        ));
    }

    #[test]
    fn daemon_config_parses_upnp_like_tinc_net_setup() {
        tinc_test_support::assert_can_create_netns();
        let defaults = RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha")])).unwrap();
        assert_eq!(UpnpMode::Off, defaults.daemon.upnp.mode);
        assert_eq!(5, defaults.daemon.upnp.discover_wait);
        assert_eq!(60, defaults.daemon.upnp.refresh_period);
        assert!(!defaults.daemon.upnp.is_enabled());

        let yes = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("UPnP", "yes"),
            ("UPnPDiscoverWait", "9"),
            ("UPnPRefreshPeriod", "11"),
        ]))
        .unwrap();
        assert_eq!(UpnpMode::TcpAndUdp, yes.daemon.upnp.mode);
        assert!(yes.daemon.upnp.maps_tcp());
        assert!(yes.daemon.upnp.maps_udp());
        assert_eq!(9, yes.daemon.upnp.discover_wait);
        assert_eq!(11, yes.daemon.upnp.refresh_period);

        let udp = RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("UPnP", "udponly")]))
            .unwrap();
        assert_eq!(UpnpMode::UdpOnly, udp.daemon.upnp.mode);
        assert!(!udp.daemon.upnp.maps_tcp());
        assert!(udp.daemon.upnp.maps_udp());

        let bogus = RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("UPnP", "maybe")]))
            .unwrap();
        assert_eq!(
            UpnpMode::Off,
            bogus.daemon.upnp.mode,
            "C setup_myself() ignores UPnP values other than yes and udponly"
        );
    }

    #[test]
    fn daemon_config_parses_tun_and_tap_device_types() {
        tinc_test_support::assert_can_create_netns();
        let tun =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("DeviceType", "tun")]))
                .unwrap();
        let tap =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("DeviceType", "tap")]))
                .unwrap();

        assert_eq!(DeviceType::Tun, tun.daemon.device.device_type);
        assert_eq!(DeviceType::Tap, tap.daemon.device.device_type);
    }

    #[test]
    fn runtime_config_parses_supported_modes_case_insensitively() {
        tinc_test_support::assert_can_create_netns();
        let tree = tree(&[
            ("Name", "alpha"),
            ("Mode", "Switch"),
            ("Forwarding", "Kernel"),
            ("Broadcast", "direct"),
            ("DirectOnly", "yes"),
            ("DecrementTTL", "yes"),
            ("PriorityInheritance", "yes"),
        ]);

        let config = RuntimeConfig::from_config_tree(&tree).unwrap();

        assert_eq!(RoutingMode::Switch, config.engine.route.routing_mode);
        assert_eq!(ForwardingMode::Kernel, config.engine.route.forwarding_mode);
        assert_eq!(BroadcastMode::Direct, config.engine.broadcast);
        assert!(config.engine.route.direct_only);
        assert!(config.engine.route.decrement_ttl);
        assert!(config.engine.route.priority_inheritance);
    }

    #[test]
    fn tunnel_server_enables_meta_tunnel_mode_and_strict_subnets() {
        tinc_test_support::assert_can_create_netns();
        let tree = tree(&[
            ("Name", "alpha"),
            ("TunnelServer", "yes"),
            ("Broadcast", "direct"),
        ]);

        let config = RuntimeConfig::from_config_tree(&tree).unwrap();

        assert!(config.tunnel_server);
        assert!(config.strict_subnets);
        assert_eq!(MetaNetworkMode::TunnelServer, config.meta_network_mode);
        assert_eq!(
            BroadcastMode::None,
            config.engine.broadcast,
            "C broadcast_packet() stops forwarding broadcasts in TunnelServer mode before applying Broadcast"
        );
    }

    #[test]
    fn tunnel_server_still_validates_broadcast_mode_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let err = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("TunnelServer", "yes"),
            ("Broadcast", "flood"),
        ]))
        .unwrap_err();

        assert_eq!(
            RuntimeConfigError::InvalidBroadcastMode("flood".to_owned()),
            err
        );
    }

    #[test]
    fn runtime_config_parses_autoconnect_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let config =
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("AutoConnect", "no")]))
                .unwrap();

        assert!(!config.autoconnect);
    }

    #[test]
    fn runtime_config_parses_http_proxy_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let config = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("Proxy", "http proxy.example 3128 user pass"),
        ]))
        .unwrap();

        assert_eq!(
            ProxyConfig::Http {
                host: "proxy.example".to_owned(),
                port: "3128".to_owned(),
                user: Some("user".to_owned()),
                password: Some("pass".to_owned()),
            },
            config.daemon.proxy
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidProxy(
                "http proxy.example".to_owned()
            )),
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "http proxy.example")
            ]))
        );
        assert_eq!(
            ProxyConfig::Socks5 {
                host: "127.0.0.1".to_owned(),
                port: "1080".to_owned(),
                user: None,
                password: None,
            },
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "socks5 127.0.0.1 1080")
            ]))
            .unwrap()
            .daemon
            .proxy
        );
        assert_eq!(
            ProxyConfig::Socks5 {
                host: "127.0.0.1".to_owned(),
                port: "1080".to_owned(),
                user: Some("user".to_owned()),
                password: Some("pass".to_owned()),
            },
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "socks5 127.0.0.1 1080 user pass")
            ]))
            .unwrap()
            .daemon
            .proxy
        );
        assert_eq!(
            ProxyConfig::Socks4 {
                host: "127.0.0.1".to_owned(),
                port: "1080".to_owned(),
                user: Some("alice".to_owned()),
            },
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "socks4 127.0.0.1 1080 alice")
            ]))
            .unwrap()
            .daemon
            .proxy
        );
        assert_eq!(
            ProxyConfig::Socks4a {
                host: "127.0.0.1".to_owned(),
                port: "1080".to_owned(),
                user: Some("user".to_owned()),
                password: Some("pass".to_owned()),
            },
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "socks4a 127.0.0.1 1080 user pass")
            ]))
            .unwrap()
            .daemon
            .proxy
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidProxy(
                "socks4a 127.0.0.1".to_owned()
            )),
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "socks4a 127.0.0.1")
            ]))
        );
        assert_eq!(
            ProxyConfig::Exec {
                command: "/usr/bin/proxy --flag beta".to_owned(),
            },
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Proxy", "exec /usr/bin/proxy --flag beta")
            ]))
            .unwrap()
            .daemon
            .proxy
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidProxy("exec".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Proxy", "exec")]))
        );
    }

    #[test]
    fn runtime_config_parses_experimental_protocol_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let config = RuntimeConfig::from_config_tree(&tree(&[
            ("Name", "alpha"),
            ("ExperimentalProtocol", "no"),
        ]))
        .unwrap();

        assert_eq!(Some(false), config.experimental_protocol);
        assert!(!config.state.experimental);
        assert!(!config.state.graph.node("alpha").unwrap().status.sptps);

        let default = RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha")])).unwrap();
        assert_eq!(None, default.experimental_protocol);
        assert!(default.state.experimental);
        assert!(default.state.graph.node("alpha").unwrap().status.sptps);
    }

    #[test]
    fn host_configs_capture_peer_meta_options_for_ack() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha")]);
        let beta = tree(&[
            ("IndirectData", "yes"),
            ("ClampMSS", "no"),
            ("Weight", "21"),
        ]);
        let gamma = tree(&[
            ("TCPOnly", "yes"),
            ("ClampMSS", "not-a-bool"),
            ("Weight", "not-an-int"),
        ]);

        let config = RuntimeConfig::from_config_tree_with_hosts(
            &server,
            [("beta", &beta), ("gamma", &gamma)],
        )
        .unwrap();

        assert_eq!(
            Some(&PeerMetaConfig {
                indirect_data: true,
                tcp_only: false,
                clamp_mss: Some(false),
                weight: Some(21),
            }),
            config.peer_meta_configs.get("beta")
        );
        assert_eq!(
            Some(&PeerMetaConfig {
                indirect_data: false,
                tcp_only: true,
                clamp_mss: None,
                weight: None,
            }),
            config.peer_meta_configs.get("gamma")
        );
    }

    #[test]
    fn host_configs_create_known_nodes_without_strict_subnets() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha")]);
        let beta = tree(&[("Address", "192.0.2.2 1234"), ("Subnet", "10.2.0.0/16")]);
        let gamma = tree(&[("Subnet", "10.3.0.0/16")]);

        let config = RuntimeConfig::from_config_tree_with_hosts(
            &server,
            [("beta", &beta), ("gamma", &gamma)],
        )
        .unwrap();

        assert!(config.state.graph.node("beta").unwrap().status.has_address);
        assert_eq!(
            Some("192.0.2.2:1234".parse().unwrap()),
            config.addresses.address("beta")
        );
        assert!(config.state.graph.node("gamma").is_some());
        assert_eq!(
            Vec::<String>::new(),
            config
                .state
                .subnets
                .owner_subnets("beta")
                .map(|subnet| subnet.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn host_address_table_resolves_names_and_uses_host_port_default_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
        let beta = tree(&[
            ("Port", "777"),
            ("Address", "localhost 655"),
            ("Address", "2001:db8::2"),
        ]);
        let gamma = tree(&[("Address", "198.51.100.9")]);

        let config = RuntimeConfig::from_config_tree_with_hosts(
            &server,
            [("beta", &beta), ("gamma", &gamma)],
        )
        .unwrap();

        assert_eq!(
            Some("127.0.0.1:655".parse().unwrap()),
            config.addresses.address("beta")
        );
        assert_eq!(
            Some(&["127.0.0.1:655".parse().unwrap()][..]),
            config.addresses.addresses("beta")
        );
        assert_eq!(
            Some("198.51.100.9:655".parse().unwrap()),
            config.addresses.address("gamma")
        );
    }

    #[test]
    fn host_address_table_resolves_service_names_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
        let beta = tree(&[("Address", "localhost http")]);

        let config =
            RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta)]).unwrap();

        assert_eq!(
            Some("127.0.0.1:80".parse().unwrap()),
            config.addresses.address("beta")
        );
    }

    #[test]
    fn strict_subnets_loads_remote_host_subnets_and_ignores_bad_remote_entries() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha"), ("StrictSubnets", "yes")]);
        let beta = tree(&[
            ("Subnet", "10.2.0.0/16"),
            ("Subnet", "10.2.0.1/24"),
            ("Subnet", "not-a-subnet"),
        ]);

        let config =
            RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta)]).unwrap();

        assert_eq!(
            vec!["10.2.0.0/16"],
            config
                .state
                .subnets
                .owner_subnets("beta")
                .map(|subnet| subnet.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn host_configs_skip_local_host_to_avoid_duplicate_local_subnets() {
        tinc_test_support::assert_can_create_netns();
        let server = tree(&[("Name", "alpha"), ("Subnet", "10.1.0.0/16")]);
        let alpha = tree(&[("Subnet", "10.99.0.0/16")]);

        let config =
            RuntimeConfig::from_config_tree_with_hosts(&server, [("alpha", &alpha)]).unwrap();

        assert_eq!(
            vec!["10.1.0.0/16"],
            config
                .state
                .subnets
                .owner_subnets("alpha")
                .map(|subnet| subnet.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn runtime_config_rejects_missing_and_invalid_values() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(RuntimeConfigError::MissingRequired { variable: "Name" }),
            RuntimeConfig::from_config_tree(&ConfigTree::new())
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidName("bad-name".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "bad-name")]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidRoutingMode("bridge".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Mode", "bridge")]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidForwardingMode(
                "userspace".to_owned()
            )),
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Forwarding", "userspace")
            ]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidBroadcastMode("flood".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Broadcast", "flood")]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidAddressFamily("ipx".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("AddressFamily", "ipx")]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidProcessPriority(
                "urgent".to_owned()
            )),
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("ProcessPriority", "urgent")
            ]))
        );
        assert_eq!(
            Err(RuntimeConfigError::InvalidSandboxLevel("medium".to_owned())),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Sandbox", "medium")]))
        );
        #[cfg(target_os = "openbsd")]
        assert_eq!(
            SandboxLevel::Normal,
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha")]))
                .unwrap()
                .daemon
                .sandbox
        );
        #[cfg(not(target_os = "openbsd"))]
        assert_eq!(
            Err(RuntimeConfigError::UnsupportedSandboxLevel(
                SandboxLevel::Normal
            )),
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Sandbox", "normal")]))
        );
        #[cfg(target_os = "openbsd")]
        assert_eq!(
            SandboxLevel::Normal,
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("Sandbox", "normal")]))
                .unwrap()
                .daemon
                .sandbox
        );
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("StrictSubnets", "true")])),
            Err(RuntimeConfigError::Bool(ConfigValueError::Bool { variable }))
                if variable == "StrictSubnets"
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("Subnet", "10.0.0.1/24")
            ])),
            Err(RuntimeConfigError::SubnetMask { variable, value })
                if variable == "Subnet" && value == "10.0.0.1/24"
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("UDPRcvBuf", "-1")])),
            Err(RuntimeConfigError::NegativeInteger {
                variable: "UDPRcvBuf",
                value: -1
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("UDPSndBuf", "-2")])),
            Err(RuntimeConfigError::NegativeInteger {
                variable: "UDPSndBuf",
                value: -2
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("ReplayWindow", "-3")])),
            Err(RuntimeConfigError::NegativeInteger {
                variable: "ReplayWindow",
                value: -3
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("MaxOutputBufferSize", "-4")
            ])),
            Err(RuntimeConfigError::NegativeInteger {
                variable: "MaxOutputBufferSize",
                value: -4
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("MaxTimeout", "0")])),
            Err(RuntimeConfigError::NonPositiveInteger {
                variable: "MaxTimeout",
                value: 0
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[("Name", "alpha"), ("MaxTimeout", "-1")])),
            Err(RuntimeConfigError::NonPositiveInteger {
                variable: "MaxTimeout",
                value: -1
            })
        ));
        assert!(matches!(
            RuntimeConfig::from_config_tree(&tree(&[
                ("Name", "alpha"),
                ("MaxConnectionBurst", "0")
            ])),
            Err(RuntimeConfigError::NonPositiveInteger {
                variable: "MaxConnectionBurst",
                value: 0
            })
        ));
    }
}

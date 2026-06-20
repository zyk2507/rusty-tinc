// SPDX-License-Identifier: GPL-2.0-or-later

pub(crate) use std::borrow::Borrow;
pub(crate) use std::cell::Cell;
pub(crate) use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub(crate) use std::env;
#[cfg(unix)]
pub(crate) use std::ffi::CString;
pub(crate) use std::fmt;
pub(crate) use std::fs::{self, File, OpenOptions};
pub(crate) use std::io::{self, BufRead, BufReader, Read, Write};
pub(crate) use std::iter::Peekable;
pub(crate) use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::process::{Child, Command, Stdio};
#[cfg(unix)]
pub(crate) use std::sync::atomic::{AtomicI32, Ordering};
pub(crate) use std::sync::mpsc;
pub(crate) use std::thread;
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
pub(crate) use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
pub(crate) use std::os::unix::ffi::OsStrExt;

pub(crate) use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
pub(crate) use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
pub(crate) use sha2::{Digest, Sha512};
pub(crate) use tinc_core::config::{Config, ConfigLoadError, ConfigParseError, ConfigTree};
pub(crate) use tinc_core::graph::{
    DEFAULT_MTU, Edge, EdgeEndpoint, MIN_MTU, Node, NodeId, NodeStatus, OPTION_CLAMP_MSS,
    OPTION_INDIRECT, OPTION_PMTU_DISCOVERY, OPTION_TCPONLY, option_version,
};
pub(crate) use tinc_core::protocol::{
    AddEdgeMessage, AnswerKeyMessage, DeleteEdgeMessage, EdgeAddress, KeyChangedMessage,
    MetaMessage, MtuInfoMessage, PROT_MAJOR, PROT_MINOR, PastRequestCache, Request,
    RequestKeyExtension, RequestKeyMessage, SubnetMessage, UdpInfoMessage, parse_meta_message,
};
pub(crate) use tinc_core::route::{ForwardingMode, RoutingMode};
pub(crate) use tinc_core::state::{NetworkState, PurgeOptions, StateMutation};
pub(crate) use tinc_core::subnet::Subnet;
pub(crate) use tinc_core::utils::{b64encode_tinc_urlsafe, bin_to_hex, check_id, check_netname};
pub(crate) use tinc_runtime::config::{
    DeviceConfig, DeviceType, ListenAddress, ListenAddressFamily, PeerMetaConfig, ProcessPriority,
    ProxyConfig, RuntimeConfig, RuntimeConfigError, SandboxLevel,
};
pub(crate) use tinc_runtime::device::{
    Device, DeviceError, DeviceInfo, DeviceKind, DummyDevice, FileDevice, FrameMode, MemoryDevice,
    VpnPacket,
};
pub(crate) use tinc_runtime::engine::{
    EngineConfig, EngineError, EngineEvent, PacketTransport, TransportError,
    handle_device_packet_with, handle_network_packet_with,
};
pub(crate) use tinc_runtime::key_exchange::{
    SptpsKeyExchange, SptpsKeyExchangeError, SptpsKeyExchangeEvent, SptpsKeyExchangeResult,
};
pub(crate) use tinc_runtime::legacy_meta::{
    LEGACY_META_PROTOCOL_MINOR, LEGACY_META_UPGRADE_PROTOCOL_MINOR, LegacyMetaAuth,
    LegacyMetaConnectionDriver, LegacyMetaConnectionError, LegacyMetaError, LegacyMetaPrivateKey,
    legacy_meta_private_decrypt_components, legacy_meta_private_decrypt_pem,
    rsa_size as legacy_meta_rsa_size,
};
pub(crate) use tinc_runtime::meta::{
    MetaAuthEvent, MetaAuthState, MetaConnectionAuth, MetaConnectionDriver, MetaConnectionError,
    MetaConnectionEvent, MetaStreamDecoder, MetaStreamFrame,
};
pub(crate) use tinc_runtime::sptps::{
    DEFAULT_SPTPS_REPLAY_WINDOW_BYTES, SPTPS_DATAGRAM_OVERHEAD, SptpsError, SptpsHandshakeEvent,
    SptpsHandshakeSession, TincEd25519PrivateKey, TincEd25519PublicKey,
};
pub(crate) use tinc_runtime::transport::{
    CompressionLevel, DEFAULT_REPLAY_WINDOW_BYTES, LEGACY_SEQNO_LEN, LegacyCipherAlgorithm,
    LegacyDigest, LegacyPacketError, LegacyPeerState, LegacyUdpCodec, MAX_DATAGRAM_SIZE,
    MAX_META_BUFFER_SIZE, NodeAddressTable, NodeIdTable, PacketCodec, RELAY_HEADER_LEN,
    RelayEnvelope, SPTPS_PACKET_TYPE_MAC, SptpsPacketCodec, legacy_compression_is_available,
    sptps_packet_from_payload, sptps_payload_from_packet,
};

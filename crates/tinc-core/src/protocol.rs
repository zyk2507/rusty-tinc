// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::BTreeMap;
use std::fmt;

use crate::graph::{DEFAULT_MTU, Edge, MIN_MTU};
use crate::subnet::{Subnet, SubnetParseError};
use crate::utils::{Base64DecodeError, b64decode_tinc, b64encode_tinc, check_id};

pub const PROT_MAJOR: u8 = 17;
pub const PROT_MINOR: u8 = 7;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum Request {
    Id = 0,
    MetaKey = 1,
    Challenge = 2,
    ChallengeReply = 3,
    Ack = 4,
    Status = 5,
    Error = 6,
    TerminateRequest = 7,
    Ping = 8,
    Pong = 9,
    AddSubnet = 10,
    DeleteSubnet = 11,
    AddEdge = 12,
    DeleteEdge = 13,
    KeyChanged = 14,
    RequestKey = 15,
    AnswerKey = 16,
    Packet = 17,
    Control = 18,
    RequestPublicKey = 19,
    AnswerPublicKey = 20,
    SptpsPacket = 21,
    UdpInfo = 22,
    MtuInfo = 23,
}

impl Request {
    pub const ALL_GUARDIAN: i32 = -1;
    pub const LAST_GUARDIAN: i32 = 24;

    pub const fn number(self) -> i32 {
        self as i32
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Id => "ID",
            Self::MetaKey => "METAKEY",
            Self::Challenge => "CHALLENGE",
            Self::ChallengeReply => "CHAL_REPLY",
            Self::Ack => "ACK",
            Self::Status => "STATUS",
            Self::Error => "ERROR",
            Self::TerminateRequest => "TERMREQ",
            Self::Ping => "PING",
            Self::Pong => "PONG",
            Self::AddSubnet => "ADD_SUBNET",
            Self::DeleteSubnet => "DEL_SUBNET",
            Self::AddEdge => "ADD_EDGE",
            Self::DeleteEdge => "DEL_EDGE",
            Self::KeyChanged => "KEY_CHANGED",
            Self::RequestKey => "REQ_KEY",
            Self::AnswerKey => "ANS_KEY",
            Self::Packet => "PACKET",
            Self::Control => "CONTROL",
            Self::RequestPublicKey => "REQ_PUBKEY",
            Self::AnswerPublicKey => "ANS_PUBKEY",
            Self::SptpsPacket => "SPTPS_PACKET",
            Self::UdpInfo => "UDP_INFO",
            Self::MtuInfo => "MTU_INFO",
        }
    }

    pub const fn has_handler(self) -> bool {
        !matches!(
            self,
            Self::Status | Self::Error | Self::RequestPublicKey | Self::AnswerPublicKey
        )
    }

    pub const fn entry(self) -> RequestEntry {
        RequestEntry {
            request: self,
            name: self.name(),
            has_handler: self.has_handler(),
        }
    }
}

impl TryFrom<i32> for Request {
    type Error = InvalidRequest;

    fn try_from(value: i32) -> Result<Self, InvalidRequest> {
        request_from_number(value).ok_or(InvalidRequest(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestEntry {
    pub request: Request,
    pub name: &'static str,
    pub has_handler: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRequest(pub i32);

impl fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid request {}", self.0)
    }
}

impl std::error::Error for InvalidRequest {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestLineError {
    BogusData,
    UnknownRequest(i32),
    UnhandledRequest(Request),
}

impl fmt::Display for RequestLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BogusData => write!(f, "bogus request data"),
            Self::UnknownRequest(request) => write!(f, "unknown request {request}"),
            Self::UnhandledRequest(request) => {
                write!(f, "request {} has no handler", request.name())
            }
        }
    }
}

impl std::error::Error for RequestLineError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLine<'a> {
    pub request: Request,
    pub raw: &'a str,
    pub arguments: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaMessage {
    Id(IdMessage),
    MetaKey(MetaKeyMessage),
    Challenge(ChallengeMessage),
    ChallengeReply(ChallengeReplyMessage),
    Ack(AckMessage),
    TerminateRequest,
    Ping,
    Pong,
    AddSubnet(SubnetMessage),
    DeleteSubnet(SubnetMessage),
    AddEdge(AddEdgeMessage),
    DeleteEdge(DeleteEdgeMessage),
    KeyChanged(KeyChangedMessage),
    RequestKey(RequestKeyMessage),
    AnswerKey(AnswerKeyMessage),
    TcpPacket(TcpPacketMessage),
    SptpsTcpPacket(TcpPacketMessage),
    UdpInfo(UdpInfoMessage),
    MtuInfo(MtuInfoMessage),
}

impl MetaMessage {
    pub fn request(&self) -> Request {
        match self {
            Self::Id(_) => Request::Id,
            Self::MetaKey(_) => Request::MetaKey,
            Self::Challenge(_) => Request::Challenge,
            Self::ChallengeReply(_) => Request::ChallengeReply,
            Self::Ack(_) => Request::Ack,
            Self::TerminateRequest => Request::TerminateRequest,
            Self::Ping => Request::Ping,
            Self::Pong => Request::Pong,
            Self::AddSubnet(_) => Request::AddSubnet,
            Self::DeleteSubnet(_) => Request::DeleteSubnet,
            Self::AddEdge(_) => Request::AddEdge,
            Self::DeleteEdge(_) => Request::DeleteEdge,
            Self::KeyChanged(_) => Request::KeyChanged,
            Self::RequestKey(_) => Request::RequestKey,
            Self::AnswerKey(_) => Request::AnswerKey,
            Self::TcpPacket(_) => Request::Packet,
            Self::SptpsTcpPacket(_) => Request::SptpsPacket,
            Self::UdpInfo(_) => Request::UdpInfo,
            Self::MtuInfo(_) => Request::MtuInfo,
        }
    }
}

impl fmt::Display for MetaMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(message) => write!(
                f,
                "{} {} {}.{}",
                Request::Id.number(),
                message.name,
                message.protocol_major,
                message.protocol_minor.unwrap_or(0)
            ),
            Self::MetaKey(message) => write!(
                f,
                "{} {} {} {} {} {}",
                Request::MetaKey.number(),
                message.cipher,
                message.digest,
                message.mac_length,
                message.compression,
                message.key
            ),
            Self::Challenge(message) => {
                write!(f, "{} {}", Request::Challenge.number(), message.data)
            }
            Self::ChallengeReply(message) => {
                write!(f, "{} {}", Request::ChallengeReply.number(), message.digest)
            }
            Self::Ack(message) => match message {
                AckMessage::Connection {
                    port,
                    weight,
                    options,
                } => write!(
                    f,
                    "{} {} {} {:x}",
                    Request::Ack.number(),
                    port,
                    weight,
                    options
                ),
                AckMessage::Payload(payload) => {
                    write!(f, "{} {}", Request::Ack.number(), payload)
                }
                AckMessage::Control { version, pid } => {
                    write!(f, "{} {} {}", Request::Ack.number(), version, pid)
                }
            },
            Self::TerminateRequest => write!(f, "{}", Request::TerminateRequest.number()),
            Self::Ping => write!(f, "{}", Request::Ping.number()),
            Self::Pong => write!(f, "{}", Request::Pong.number()),
            Self::AddSubnet(message) => write!(
                f,
                "{} {:x} {} {}",
                Request::AddSubnet.number(),
                message.nonce,
                message.owner,
                message.subnet
            ),
            Self::DeleteSubnet(message) => write!(
                f,
                "{} {:x} {} {}",
                Request::DeleteSubnet.number(),
                message.nonce,
                message.owner,
                message.subnet
            ),
            Self::AddEdge(message) => {
                write!(
                    f,
                    "{} {:x} {} {} {} {} {:x} {}",
                    Request::AddEdge.number(),
                    message.nonce,
                    message.edge.from,
                    message.edge.to,
                    message.address,
                    message.port,
                    message.edge.options,
                    message.edge.weight
                )?;

                if let Some(local) = &message.local {
                    write!(f, " {} {}", local.address, local.port)?;
                }

                Ok(())
            }
            Self::DeleteEdge(message) => write!(
                f,
                "{} {:x} {} {}",
                Request::DeleteEdge.number(),
                message.nonce,
                message.from,
                message.to
            ),
            Self::KeyChanged(message) => write!(
                f,
                "{} {:x} {}",
                Request::KeyChanged.number(),
                message.nonce,
                message.origin
            ),
            Self::RequestKey(message) => {
                write!(
                    f,
                    "{} {} {}",
                    Request::RequestKey.number(),
                    message.from,
                    message.to
                )?;

                if let Some(extension) = &message.extension {
                    write!(f, " {}", extension.request)?;

                    if let Some(payload) = &extension.payload {
                        write!(f, " {payload}")?;
                    }
                }

                Ok(())
            }
            Self::AnswerKey(message) => {
                write!(
                    f,
                    "{} {} {} {} {} {} {} {}",
                    Request::AnswerKey.number(),
                    message.from,
                    message.to,
                    message.key,
                    message.cipher,
                    message.digest,
                    message.mac_length,
                    message.compression
                )?;

                if let Some(address) = &message.address {
                    write!(f, " {} {}", address.address, address.port)?;
                }

                Ok(())
            }
            Self::TcpPacket(message) => {
                write!(f, "{} {}", Request::Packet.number(), message.length)
            }
            Self::SptpsTcpPacket(message) => {
                write!(f, "{} {}", Request::SptpsPacket.number(), message.length)
            }
            Self::UdpInfo(message) => write!(
                f,
                "{} {} {} {} {}",
                Request::UdpInfo.number(),
                message.from,
                message.to,
                message.endpoint.address,
                message.endpoint.port
            ),
            Self::MtuInfo(message) => write!(
                f,
                "{} {} {} {}",
                Request::MtuInfo.number(),
                message.from,
                message.to,
                message.mtu
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdMessage {
    pub name: String,
    pub protocol_major: i32,
    pub protocol_minor: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaKeyMessage {
    pub cipher: i32,
    pub digest: i32,
    pub mac_length: i32,
    pub compression: i32,
    pub key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeMessage {
    pub data: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeReplyMessage {
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AckMessage {
    Connection {
        port: String,
        weight: i32,
        options: u32,
    },
    Payload(String),
    Control {
        version: i32,
        pid: i32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetMessage {
    pub nonce: u32,
    pub owner: String,
    pub subnet: Subnet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddEdgeMessage {
    pub nonce: u32,
    pub edge: Edge,
    pub address: String,
    pub port: String,
    pub local: Option<EdgeAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteEdgeMessage {
    pub nonce: u32,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeAddress {
    pub address: String,
    pub port: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyChangedMessage {
    pub nonce: u32,
    pub origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestKeyMessage {
    pub from: String,
    pub to: String,
    pub extension: Option<RequestKeyExtension>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestKeyExtension {
    pub request: i32,
    pub payload: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnswerKeyMessage {
    pub from: String,
    pub to: String,
    pub key: String,
    pub cipher: i32,
    pub digest: i32,
    pub mac_length: u64,
    pub compression: i32,
    pub address: Option<EdgeAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpPacketMessage {
    pub length: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpInfoMessage {
    pub from: String,
    pub to: String,
    pub endpoint: EdgeAddress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtuInfoMessage {
    pub from: String,
    pub to: String,
    pub mtu: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SptpsKeyPayloadKind {
    InitialRequest,
    HandshakeAnswer,
    TcpPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsKeyPayload {
    pub from: String,
    pub to: String,
    pub kind: SptpsKeyPayloadKind,
    pub data: Vec<u8>,
    pub compression: Option<i32>,
    pub address: Option<EdgeAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SptpsKeyPayloadError {
    NotSptps,
    MissingPayload,
    InvalidBase64(Base64DecodeError),
}

impl fmt::Display for SptpsKeyPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSptps => write!(f, "key message does not carry SPTPS data"),
            Self::MissingPayload => write!(f, "SPTPS key message is missing payload data"),
            Self::InvalidBase64(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SptpsKeyPayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBase64(error) => Some(error),
            _ => None,
        }
    }
}

impl RequestKeyMessage {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            extension: None,
        }
    }

    pub fn sptps_initial_request(
        from: impl Into<String>,
        to: impl Into<String>,
        data: &[u8],
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            extension: Some(RequestKeyExtension {
                request: Request::RequestKey.number(),
                payload: Some(b64encode_tinc(data)),
            }),
        }
    }

    pub fn sptps_tcp_packet(from: impl Into<String>, to: impl Into<String>, data: &[u8]) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            extension: Some(RequestKeyExtension {
                request: Request::SptpsPacket.number(),
                payload: Some(b64encode_tinc(data)),
            }),
        }
    }

    pub fn decode_sptps_payload(&self) -> Result<SptpsKeyPayload, SptpsKeyPayloadError> {
        let extension = self
            .extension
            .as_ref()
            .ok_or(SptpsKeyPayloadError::NotSptps)?;
        let kind = match Request::try_from(extension.request).ok() {
            Some(Request::RequestKey) => SptpsKeyPayloadKind::InitialRequest,
            Some(Request::SptpsPacket) => SptpsKeyPayloadKind::TcpPacket,
            _ => return Err(SptpsKeyPayloadError::NotSptps),
        };
        let payload = extension
            .payload
            .as_deref()
            .ok_or(SptpsKeyPayloadError::MissingPayload)?;
        let data = b64decode_tinc(payload).map_err(SptpsKeyPayloadError::InvalidBase64)?;

        Ok(SptpsKeyPayload {
            from: self.from.clone(),
            to: self.to.clone(),
            kind,
            data,
            compression: None,
            address: None,
        })
    }
}

impl AnswerKeyMessage {
    pub fn sptps_handshake(
        from: impl Into<String>,
        to: impl Into<String>,
        data: &[u8],
        compression: i32,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            key: b64encode_tinc(data),
            cipher: -1,
            digest: -1,
            mac_length: u64::MAX,
            compression,
            address: None,
        }
    }

    pub fn with_address(mut self, address: impl Into<String>, port: impl Into<String>) -> Self {
        self.address = Some(EdgeAddress {
            address: address.into(),
            port: port.into(),
        });
        self
    }

    pub fn is_sptps_handshake(&self) -> bool {
        self.cipher == -1 && self.digest == -1 && self.mac_length == u64::MAX
    }

    pub fn decode_sptps_payload(&self) -> Result<SptpsKeyPayload, SptpsKeyPayloadError> {
        if !self.is_sptps_handshake() {
            return Err(SptpsKeyPayloadError::NotSptps);
        }

        let data = b64decode_tinc(&self.key).map_err(SptpsKeyPayloadError::InvalidBase64)?;

        Ok(SptpsKeyPayload {
            from: self.from.clone(),
            to: self.to.clone(),
            kind: SptpsKeyPayloadKind::HandshakeAnswer,
            data,
            compression: Some(self.compression),
            address: self.address.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaMessageError {
    RequestLine(RequestLineError),
    UnsupportedRequest(Request),
    MissingField(&'static str),
    InvalidNonce(String),
    InvalidProtocolVersion(String),
    InvalidOptions(String),
    InvalidWeight(String),
    InvalidInteger { field: &'static str, value: String },
    InvalidLength(i32),
    InvalidMtu(i32),
    InvalidName(String),
    SelfEdge(String),
    InvalidSubnet(SubnetParseError),
}

impl fmt::Display for MetaMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestLine(error) => write!(f, "{error}"),
            Self::UnsupportedRequest(request) => {
                write!(f, "unsupported meta message {}", request.name())
            }
            Self::MissingField(field) => write!(f, "missing field {field}"),
            Self::InvalidNonce(value) => write!(f, "invalid nonce {value}"),
            Self::InvalidProtocolVersion(value) => {
                write!(f, "invalid protocol version {value}")
            }
            Self::InvalidOptions(value) => write!(f, "invalid edge options {value}"),
            Self::InvalidWeight(value) => write!(f, "invalid edge weight {value}"),
            Self::InvalidInteger { field, value } => {
                write!(f, "invalid integer for {field}: {value}")
            }
            Self::InvalidLength(value) => write!(f, "invalid packet length {value}"),
            Self::InvalidMtu(value) => write!(f, "invalid MTU {value}"),
            Self::InvalidName(value) => write!(f, "invalid node name {value}"),
            Self::SelfEdge(value) => write!(f, "edge points from and to the same node {value}"),
            Self::InvalidSubnet(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MetaMessageError {}

pub const REQUESTS: [RequestEntry; Request::LAST_GUARDIAN as usize] = [
    Request::Id.entry(),
    Request::MetaKey.entry(),
    Request::Challenge.entry(),
    Request::ChallengeReply.entry(),
    Request::Ack.entry(),
    Request::Status.entry(),
    Request::Error.entry(),
    Request::TerminateRequest.entry(),
    Request::Ping.entry(),
    Request::Pong.entry(),
    Request::AddSubnet.entry(),
    Request::DeleteSubnet.entry(),
    Request::AddEdge.entry(),
    Request::DeleteEdge.entry(),
    Request::KeyChanged.entry(),
    Request::RequestKey.entry(),
    Request::AnswerKey.entry(),
    Request::Packet.entry(),
    Request::Control.entry(),
    Request::RequestPublicKey.entry(),
    Request::AnswerPublicKey.entry(),
    Request::SptpsPacket.entry(),
    Request::UdpInfo.entry(),
    Request::MtuInfo.entry(),
];

pub fn get_request_entry(request: i32) -> Option<RequestEntry> {
    request_from_number(request).map(Request::entry)
}

pub const fn request_from_number(request: i32) -> Option<Request> {
    match request {
        0 => Some(Request::Id),
        1 => Some(Request::MetaKey),
        2 => Some(Request::Challenge),
        3 => Some(Request::ChallengeReply),
        4 => Some(Request::Ack),
        5 => Some(Request::Status),
        6 => Some(Request::Error),
        7 => Some(Request::TerminateRequest),
        8 => Some(Request::Ping),
        9 => Some(Request::Pong),
        10 => Some(Request::AddSubnet),
        11 => Some(Request::DeleteSubnet),
        12 => Some(Request::AddEdge),
        13 => Some(Request::DeleteEdge),
        14 => Some(Request::KeyChanged),
        15 => Some(Request::RequestKey),
        16 => Some(Request::AnswerKey),
        17 => Some(Request::Packet),
        18 => Some(Request::Control),
        19 => Some(Request::RequestPublicKey),
        20 => Some(Request::AnswerPublicKey),
        21 => Some(Request::SptpsPacket),
        22 => Some(Request::UdpInfo),
        23 => Some(Request::MtuInfo),
        _ => None,
    }
}

pub fn parse_request_line(raw: &str) -> Result<RequestLine<'_>, RequestLineError> {
    let parsed = atoi_dispatch_prefix(raw).ok_or(RequestLineError::BogusData)?;
    let request = request_from_number(parsed.number)
        .ok_or(RequestLineError::UnknownRequest(parsed.number))?;
    let arguments = raw[parsed.end_index..].trim_start_matches(|c: char| c.is_ascii_whitespace());

    Ok(RequestLine {
        request,
        raw,
        arguments,
    })
}

pub fn parse_dispatchable_request_line(raw: &str) -> Result<RequestLine<'_>, RequestLineError> {
    let line = parse_request_line(raw)?;

    if !line.request.has_handler() {
        return Err(RequestLineError::UnhandledRequest(line.request));
    }

    Ok(line)
}

pub fn parse_meta_message(raw: &str) -> Result<MetaMessage, MetaMessageError> {
    let line = parse_request_line(raw).map_err(MetaMessageError::RequestLine)?;

    match line.request {
        Request::Id => parse_id_message(line.arguments).map(MetaMessage::Id),
        Request::MetaKey => parse_metakey_message(line.arguments).map(MetaMessage::MetaKey),
        Request::Challenge => parse_challenge_message(line.arguments).map(MetaMessage::Challenge),
        Request::ChallengeReply => {
            parse_challenge_reply_message(line.arguments).map(MetaMessage::ChallengeReply)
        }
        Request::Ack => parse_ack_message(line.arguments).map(MetaMessage::Ack),
        Request::TerminateRequest => Ok(MetaMessage::TerminateRequest),
        Request::Ping => Ok(MetaMessage::Ping),
        Request::Pong => Ok(MetaMessage::Pong),
        Request::AddSubnet => parse_subnet_message(line.arguments).map(MetaMessage::AddSubnet),
        Request::DeleteSubnet => {
            parse_subnet_message(line.arguments).map(MetaMessage::DeleteSubnet)
        }
        Request::AddEdge => parse_add_edge_message(line.arguments).map(MetaMessage::AddEdge),
        Request::DeleteEdge => {
            parse_delete_edge_message(line.arguments).map(MetaMessage::DeleteEdge)
        }
        Request::KeyChanged => {
            parse_key_changed_message(line.arguments).map(MetaMessage::KeyChanged)
        }
        Request::RequestKey => {
            parse_request_key_message(line.arguments).map(MetaMessage::RequestKey)
        }
        Request::AnswerKey => parse_answer_key_message(line.arguments).map(MetaMessage::AnswerKey),
        Request::Packet => parse_tcp_packet_message(line.arguments).map(MetaMessage::TcpPacket),
        Request::SptpsPacket => {
            parse_tcp_packet_message(line.arguments).map(MetaMessage::SptpsTcpPacket)
        }
        Request::UdpInfo => parse_udp_info_message(line.arguments).map(MetaMessage::UdpInfo),
        Request::MtuInfo => parse_mtu_info_message(line.arguments).map(MetaMessage::MtuInfo),
        request => Err(MetaMessageError::UnsupportedRequest(request)),
    }
}

#[derive(Clone, Debug)]
pub struct PastRequestCache {
    retention_secs: u64,
    entries: BTreeMap<String, u64>,
}

impl PastRequestCache {
    pub fn new(retention_secs: u64) -> Self {
        Self {
            retention_secs,
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn mark_seen(&mut self, request: &str, now_secs: u64) -> bool {
        self.age(now_secs);

        if self.entries.contains_key(request) {
            return true;
        }

        self.entries.insert(request.to_owned(), now_secs);
        false
    }

    pub fn age(&mut self, now_secs: u64) -> usize {
        let before = self.entries.len();
        let retention_secs = self.retention_secs;

        self.entries
            .retain(|_, first_seen| first_seen.saturating_add(retention_secs) > now_secs);

        before - self.entries.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AtoiPrefix {
    number: i32,
    end_index: usize,
}

fn atoi_dispatch_prefix(input: &str) -> Option<AtoiPrefix> {
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
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

    let digit_start = index;
    let mut number = 0i64;

    while index < bytes.len() && bytes[index].is_ascii_digit() {
        number = number
            .saturating_mul(10)
            .saturating_add((bytes[index] - b'0') as i64);
        index += 1;
    }

    if digit_start == index {
        number = 0;
    }

    if negative {
        number = -number;
    }

    let number = number.clamp(i32::MIN as i64, i32::MAX as i64) as i32;

    if number != 0 || input.as_bytes().first() == Some(&b'0') {
        return Some(AtoiPrefix {
            number,
            end_index: index,
        });
    }

    None
}

fn parse_id_message(arguments: &str) -> Result<IdMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let name = next_field(&mut fields, "name")?;
    let version = next_field(&mut fields, "version")?;
    let (protocol_major, protocol_minor) = parse_protocol_version(version)?;

    if !is_special_id_name(name) {
        validate_node_name(name)?;
    }

    Ok(IdMessage {
        name: name.to_owned(),
        protocol_major,
        protocol_minor,
    })
}

fn parse_metakey_message(arguments: &str) -> Result<MetaKeyMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let cipher = parse_i32_field("cipher", next_field(&mut fields, "cipher")?)?;
    let digest = parse_i32_field("digest", next_field(&mut fields, "digest")?)?;
    let mac_length = parse_i32_field("mac_length", next_field(&mut fields, "mac_length")?)?;
    let compression = parse_i32_field("compression", next_field(&mut fields, "compression")?)?;
    let key = next_field(&mut fields, "key")?;

    Ok(MetaKeyMessage {
        cipher,
        digest,
        mac_length,
        compression,
        key: key.to_owned(),
    })
}

fn parse_challenge_message(arguments: &str) -> Result<ChallengeMessage, MetaMessageError> {
    Ok(ChallengeMessage {
        data: next_field(&mut arguments.split_whitespace(), "challenge")?.to_owned(),
    })
}

fn parse_challenge_reply_message(
    arguments: &str,
) -> Result<ChallengeReplyMessage, MetaMessageError> {
    Ok(ChallengeReplyMessage {
        digest: next_field(&mut arguments.split_whitespace(), "digest")?.to_owned(),
    })
}

fn parse_ack_message(arguments: &str) -> Result<AckMessage, MetaMessageError> {
    let fields = arguments.split_whitespace().collect::<Vec<_>>();

    match fields.as_slice() {
        [] => Err(MetaMessageError::MissingField("ack")),
        [payload] => Ok(AckMessage::Payload((*payload).to_owned())),
        [payload, maybe_pid] => match (
            parse_i32_field("version", payload),
            parse_i32_field("pid", maybe_pid),
        ) {
            (Ok(version), Ok(pid)) => Ok(AckMessage::Control { version, pid }),
            _ => Ok(AckMessage::Payload((*payload).to_owned())),
        },
        [port, weight, options, ..] => {
            let weight = parse_i32_field("weight", weight)?;
            let options = parse_hex_u32(options)
                .ok_or_else(|| MetaMessageError::InvalidOptions((*options).to_owned()))?;

            Ok(AckMessage::Connection {
                port: (*port).to_owned(),
                weight,
                options,
            })
        }
    }
}

fn parse_subnet_message(arguments: &str) -> Result<SubnetMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let nonce = parse_nonce(next_field(&mut fields, "nonce")?)?;
    let owner = next_field(&mut fields, "owner")?;
    validate_node_name(owner)?;
    let subnet = next_field(&mut fields, "subnet")?
        .parse::<Subnet>()
        .map_err(MetaMessageError::InvalidSubnet)?;

    Ok(SubnetMessage {
        nonce,
        owner: owner.to_owned(),
        subnet,
    })
}

fn parse_add_edge_message(arguments: &str) -> Result<AddEdgeMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let nonce = parse_nonce(next_field(&mut fields, "nonce")?)?;
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_edge_names(from, to)?;
    let address = next_field(&mut fields, "address")?;
    let port = next_field(&mut fields, "port")?;
    let options_text = next_field(&mut fields, "options")?;
    let weight_text = next_field(&mut fields, "weight")?;
    let options = parse_hex_u32(options_text)
        .ok_or_else(|| MetaMessageError::InvalidOptions(options_text.to_owned()))?;
    let weight = weight_text
        .parse::<i32>()
        .map_err(|_| MetaMessageError::InvalidWeight(weight_text.to_owned()))?;
    let local = match (fields.next(), fields.next()) {
        (Some(address), Some(port)) => Some(EdgeAddress {
            address: address.to_owned(),
            port: port.to_owned(),
        }),
        (None, None) => None,
        _ => return Err(MetaMessageError::MissingField("local_port")),
    };

    Ok(AddEdgeMessage {
        nonce,
        edge: Edge::new(from, to, weight).with_options(options),
        address: address.to_owned(),
        port: port.to_owned(),
        local,
    })
}

fn parse_delete_edge_message(arguments: &str) -> Result<DeleteEdgeMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let nonce = parse_nonce(next_field(&mut fields, "nonce")?)?;
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_edge_names(from, to)?;

    Ok(DeleteEdgeMessage {
        nonce,
        from: from.to_owned(),
        to: to.to_owned(),
    })
}

fn parse_key_changed_message(arguments: &str) -> Result<KeyChangedMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let nonce = parse_nonce(next_field(&mut fields, "nonce")?)?;
    let origin = next_field(&mut fields, "origin")?;
    validate_node_name(origin)?;

    Ok(KeyChangedMessage {
        nonce,
        origin: origin.to_owned(),
    })
}

fn parse_request_key_message(arguments: &str) -> Result<RequestKeyMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_node_name(from)?;
    validate_node_name(to)?;
    let extension = match fields.next() {
        Some(request) => request.parse::<i32>().ok().map(|request| {
            let payload = fields.next().map(ToOwned::to_owned);
            RequestKeyExtension { request, payload }
        }),
        None => None,
    };

    Ok(RequestKeyMessage {
        from: from.to_owned(),
        to: to.to_owned(),
        extension,
    })
}

fn parse_answer_key_message(arguments: &str) -> Result<AnswerKeyMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_node_name(from)?;
    validate_node_name(to)?;
    let key = next_field(&mut fields, "key")?;
    let cipher = parse_i32_field("cipher", next_field(&mut fields, "cipher")?)?;
    let digest = parse_i32_field("digest", next_field(&mut fields, "digest")?)?;
    let mac_length = parse_u64_field("mac_length", next_field(&mut fields, "mac_length")?)?;
    let compression = parse_i32_field("compression", next_field(&mut fields, "compression")?)?;
    let address = match (fields.next(), fields.next()) {
        (Some(address), Some(port)) => Some(EdgeAddress {
            address: address.to_owned(),
            port: port.to_owned(),
        }),
        (None, None) => None,
        _ => return Err(MetaMessageError::MissingField("port")),
    };

    Ok(AnswerKeyMessage {
        from: from.to_owned(),
        to: to.to_owned(),
        key: key.to_owned(),
        cipher,
        digest,
        mac_length,
        compression,
        address,
    })
}

fn parse_tcp_packet_message(arguments: &str) -> Result<TcpPacketMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let length = parse_i32_field("length", next_field(&mut fields, "length")?)?;

    if !(0..=i16::MAX as i32).contains(&length) {
        return Err(MetaMessageError::InvalidLength(length));
    }

    Ok(TcpPacketMessage {
        length: length as u16,
    })
}

fn parse_udp_info_message(arguments: &str) -> Result<UdpInfoMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_node_name(from)?;
    validate_node_name(to)?;
    let address = next_field(&mut fields, "address")?;
    let port = next_field(&mut fields, "port")?;

    Ok(UdpInfoMessage {
        from: from.to_owned(),
        to: to.to_owned(),
        endpoint: EdgeAddress {
            address: address.to_owned(),
            port: port.to_owned(),
        },
    })
}

fn parse_mtu_info_message(arguments: &str) -> Result<MtuInfoMessage, MetaMessageError> {
    let mut fields = arguments.split_whitespace();
    let from = next_field(&mut fields, "from")?;
    let to = next_field(&mut fields, "to")?;
    validate_node_name(from)?;
    validate_node_name(to)?;
    let mtu = parse_i32_field("mtu", next_field(&mut fields, "mtu")?)?;

    if mtu < MIN_MTU as i32 {
        return Err(MetaMessageError::InvalidMtu(mtu));
    }

    Ok(MtuInfoMessage {
        from: from.to_owned(),
        to: to.to_owned(),
        mtu: (mtu as usize).min(DEFAULT_MTU),
    })
}

fn next_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    name: &'static str,
) -> Result<&'a str, MetaMessageError> {
    fields.next().ok_or(MetaMessageError::MissingField(name))
}

fn parse_nonce(value: &str) -> Result<u32, MetaMessageError> {
    parse_hex_u32(value).ok_or_else(|| MetaMessageError::InvalidNonce(value.to_owned()))
}

fn parse_protocol_version(value: &str) -> Result<(i32, Option<i32>), MetaMessageError> {
    let (major, minor) = match value.split_once('.') {
        Some((major, minor)) => (major, Some(minor)),
        None => (value, None),
    };

    if major.is_empty() || minor == Some("") {
        return Err(MetaMessageError::InvalidProtocolVersion(value.to_owned()));
    }

    let major = parse_i32_field("protocol_major", major)
        .map_err(|_| MetaMessageError::InvalidProtocolVersion(value.to_owned()))?;
    let minor = minor
        .map(|minor| {
            parse_i32_field("protocol_minor", minor)
                .map_err(|_| MetaMessageError::InvalidProtocolVersion(value.to_owned()))
        })
        .transpose()?;

    Ok((major, minor))
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    if value.is_empty() {
        return None;
    }

    u32::from_str_radix(value, 16).ok()
}

fn parse_i32_field(field: &'static str, value: &str) -> Result<i32, MetaMessageError> {
    value
        .parse::<i32>()
        .map_err(|_| MetaMessageError::InvalidInteger {
            field,
            value: value.to_owned(),
        })
}

fn parse_u64_field(field: &'static str, value: &str) -> Result<u64, MetaMessageError> {
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };

    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MetaMessageError::InvalidInteger {
            field,
            value: value.to_owned(),
        });
    }

    let parsed = digits.parse::<u64>().unwrap_or(u64::MAX);

    if negative {
        Ok(0u64.wrapping_sub(parsed))
    } else {
        Ok(parsed)
    }
}

fn validate_node_name(name: &str) -> Result<(), MetaMessageError> {
    if check_id(name) {
        Ok(())
    } else {
        Err(MetaMessageError::InvalidName(name.to_owned()))
    }
}

fn validate_edge_names(from: &str, to: &str) -> Result<(), MetaMessageError> {
    validate_node_name(from)?;
    validate_node_name(to)?;

    if from == to {
        return Err(MetaMessageError::SelfEdge(from.to_owned()));
    }

    Ok(())
}

fn is_special_id_name(name: &str) -> bool {
    matches!(name.as_bytes().first(), Some(b'^' | b'?')) && name.len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_invalid_request_returns_none() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(None, get_request_entry(Request::ALL_GUARDIAN));
        assert_eq!(None, get_request_entry(Request::LAST_GUARDIAN));
    }

    #[test]
    fn get_valid_request_returns_entries_with_names() {
        tinc_test_support::assert_can_create_netns();
        for request in 0..Request::LAST_GUARDIAN {
            let entry = get_request_entry(request).unwrap();
            assert_eq!(request, entry.request.number());
            assert!(!entry.name.is_empty());
        }
    }

    #[test]
    fn request_name_mapping_matches_c_table() {
        tinc_test_support::assert_can_create_netns();
        let names = REQUESTS.iter().map(|entry| entry.name).collect::<Vec<_>>();

        assert_eq!(
            vec![
                "ID",
                "METAKEY",
                "CHALLENGE",
                "CHAL_REPLY",
                "ACK",
                "STATUS",
                "ERROR",
                "TERMREQ",
                "PING",
                "PONG",
                "ADD_SUBNET",
                "DEL_SUBNET",
                "ADD_EDGE",
                "DEL_EDGE",
                "KEY_CHANGED",
                "REQ_KEY",
                "ANS_KEY",
                "PACKET",
                "CONTROL",
                "REQ_PUBKEY",
                "ANS_PUBKEY",
                "SPTPS_PACKET",
                "UDP_INFO",
                "MTU_INFO",
            ],
            names
        );
    }

    #[test]
    fn dispatchable_request_rejects_unhandled_entries() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(RequestLineError::UnhandledRequest(Request::Status)),
            parse_dispatchable_request_line("5 status")
        );
        assert_eq!(
            Err(RequestLineError::UnhandledRequest(
                Request::RequestPublicKey
            )),
            parse_dispatchable_request_line("19 node")
        );
    }

    #[test]
    fn request_line_parser_preserves_c_atoi_dispatch_rules() {
        tinc_test_support::assert_can_create_netns();
        let id = parse_request_line("0 tinc 17.7").unwrap();
        assert_eq!(Request::Id, id.request);
        assert_eq!("tinc 17.7", id.arguments);

        let metakey = parse_request_line(" 1abcdef").unwrap();
        assert_eq!(Request::MetaKey, metakey.request);
        assert_eq!("abcdef", metakey.arguments);

        assert_eq!(Err(RequestLineError::BogusData), parse_request_line(" 0"));
        assert_eq!(
            Err(RequestLineError::BogusData),
            parse_request_line("not a request")
        );
        assert_eq!(
            Err(RequestLineError::UnknownRequest(-1)),
            parse_request_line("-1")
        );
        assert_eq!(
            Err(RequestLineError::UnknownRequest(24)),
            parse_request_line("24")
        );
    }

    #[test]
    fn past_request_cache_reports_duplicates_until_aged() {
        tinc_test_support::assert_can_create_netns();
        let mut cache = PastRequestCache::new(10);

        assert!(!cache.mark_seen("10 node 192.0.2.0/24", 100));
        assert!(cache.mark_seen("10 node 192.0.2.0/24", 101));
        assert_eq!(1, cache.len());

        assert_eq!(1, cache.age(111));
        assert!(cache.is_empty());
        assert!(!cache.mark_seen("10 node 192.0.2.0/24", 111));
    }

    #[test]
    fn parse_add_and_delete_subnet_messages() {
        tinc_test_support::assert_can_create_netns();
        let add = parse_meta_message("10 7f alpha 192.0.2.0/24#42 trailing").unwrap();

        let MetaMessage::AddSubnet(add) = add else {
            panic!("expected ADD_SUBNET");
        };

        assert_eq!(0x7f, add.nonce);
        assert_eq!("alpha", add.owner);
        assert_eq!("192.0.2.0/24#42", add.subnet.to_string());

        let delete = MetaMessage::DeleteSubnet(SubnetMessage {
            nonce: 0xabcd,
            owner: "alpha".to_owned(),
            subnet: "192.0.2.0/24#42".parse().unwrap(),
        });

        assert_eq!("11 abcd alpha 192.0.2.0/24#42", delete.to_string());
    }

    #[test]
    fn parse_add_edge_message_with_optional_local_address() {
        tinc_test_support::assert_can_create_netns();
        let message = parse_meta_message(
            "12 0x42 alpha beta 203.0.113.10 655 10000001 50 10.0.0.1 655 extra",
        )
        .unwrap();

        let MetaMessage::AddEdge(add) = message else {
            panic!("expected ADD_EDGE");
        };

        assert_eq!(0x42, add.nonce);
        assert_eq!("alpha", add.edge.from);
        assert_eq!("beta", add.edge.to);
        assert_eq!("203.0.113.10", add.address);
        assert_eq!("655", add.port);
        assert_eq!(0x1000_0001, add.edge.options);
        assert_eq!(50, add.edge.weight);
        assert_eq!(
            Some(EdgeAddress {
                address: "10.0.0.1".to_owned(),
                port: "655".to_owned(),
            }),
            add.local
        );
    }

    #[test]
    fn format_add_edge_and_delete_edge_messages() {
        tinc_test_support::assert_can_create_netns();
        let add = MetaMessage::AddEdge(AddEdgeMessage {
            nonce: 0x1234,
            edge: Edge::new("alpha", "beta", 7).with_options(0xa),
            address: "198.51.100.1".to_owned(),
            port: "655".to_owned(),
            local: None,
        });
        assert_eq!("12 1234 alpha beta 198.51.100.1 655 a 7", add.to_string());

        let delete = parse_meta_message("13 ff alpha beta ignored").unwrap();
        assert_eq!(
            MetaMessage::DeleteEdge(DeleteEdgeMessage {
                nonce: 0xff,
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
            }),
            delete
        );
        assert_eq!("13 ff alpha beta", delete.to_string());
    }

    #[test]
    fn meta_message_parser_rejects_invalid_names_and_fields() {
        tinc_test_support::assert_can_create_netns();
        assert!(matches!(
            parse_meta_message("10 1 bad-name 192.0.2.0/24"),
            Err(MetaMessageError::InvalidName(_))
        ));
        assert!(matches!(
            parse_meta_message("10 1 alpha bad-subnet"),
            Err(MetaMessageError::InvalidSubnet(_))
        ));
        assert_eq!(
            Err(MetaMessageError::SelfEdge("alpha".to_owned())),
            parse_meta_message("12 1 alpha alpha 203.0.113.1 655 0 1")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidOptions("nope".to_owned())),
            parse_meta_message("12 1 alpha beta 203.0.113.1 655 nope 1")
        );
        assert_eq!(
            Err(MetaMessageError::MissingField("local_port")),
            parse_meta_message("12 1 alpha beta 203.0.113.1 655 0 1 10.0.0.1")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidName("bad-name".to_owned())),
            parse_meta_message("0 bad-name 17.7")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidProtocolVersion(
                "17.bad".to_owned()
            )),
            parse_meta_message("0 alpha 17.bad")
        );
        assert_eq!(
            Err(MetaMessageError::MissingField("key")),
            parse_meta_message("1 91 64 4 0")
        );
        assert_eq!(
            Err(MetaMessageError::MissingField("challenge")),
            parse_meta_message("2")
        );
        assert_eq!(
            Err(MetaMessageError::MissingField("digest")),
            parse_meta_message("3")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidInteger {
                field: "weight",
                value: "bad".to_owned()
            }),
            parse_meta_message("4 655 bad 0")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidLength(-1)),
            parse_meta_message("17 -1")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidLength(32768)),
            parse_meta_message("21 32768")
        );
        assert_eq!(
            Err(MetaMessageError::InvalidInteger {
                field: "length",
                value: "bad".to_owned()
            }),
            parse_meta_message("17 bad")
        );
    }

    #[test]
    fn parse_authentication_meta_messages() {
        tinc_test_support::assert_can_create_netns();
        let id = parse_meta_message("0 alpha 17.7 ignored").unwrap();
        assert_eq!(
            MetaMessage::Id(IdMessage {
                name: "alpha".to_owned(),
                protocol_major: 17,
                protocol_minor: Some(7),
            }),
            id
        );
        assert_eq!("0 alpha 17.7", id.to_string());

        assert_eq!(
            MetaMessage::Id(IdMessage {
                name: "^controlcookie".to_owned(),
                protocol_major: 17,
                protocol_minor: None,
            }),
            parse_meta_message("0 ^controlcookie 17").unwrap()
        );
        assert_eq!(
            MetaMessage::Id(IdMessage {
                name: "?invitekey".to_owned(),
                protocol_major: 17,
                protocol_minor: Some(2),
            }),
            parse_meta_message("0 ?invitekey 17.2").unwrap()
        );

        let metakey = parse_meta_message("1 91 64 4 0 deadbeef trailing").unwrap();
        assert_eq!(
            MetaMessage::MetaKey(MetaKeyMessage {
                cipher: 91,
                digest: 64,
                mac_length: 4,
                compression: 0,
                key: "deadbeef".to_owned(),
            }),
            metakey
        );
        assert_eq!("1 91 64 4 0 deadbeef", metakey.to_string());

        assert_eq!(
            MetaMessage::Challenge(ChallengeMessage {
                data: "abcdef".to_owned()
            }),
            parse_meta_message("2 abcdef trailing").unwrap()
        );
        assert_eq!(
            MetaMessage::ChallengeReply(ChallengeReplyMessage {
                digest: "012345".to_owned()
            }),
            parse_meta_message("3 012345 trailing").unwrap()
        );

        let ack = parse_meta_message("4 655 12 7000000 ignored").unwrap();
        assert_eq!(
            MetaMessage::Ack(AckMessage::Connection {
                port: "655".to_owned(),
                weight: 12,
                options: 0x0700_0000,
            }),
            ack
        );
        assert_eq!("4 655 12 7000000", ack.to_string());

        assert_eq!(
            MetaMessage::Ack(AckMessage::Payload("pubkey".to_owned())),
            parse_meta_message("4 pubkey trailing").unwrap()
        );
        assert_eq!(
            MetaMessage::Ack(AckMessage::Control {
                version: 2,
                pid: 1234,
            }),
            parse_meta_message("4 2 1234").unwrap()
        );
    }

    #[test]
    fn parse_simple_connection_meta_messages() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            MetaMessage::TerminateRequest,
            parse_meta_message("7 ignored like c handler").unwrap()
        );
        assert_eq!(
            MetaMessage::Ping,
            parse_meta_message("8 ignored like c handler").unwrap()
        );
        assert_eq!(
            MetaMessage::Pong,
            parse_meta_message("9 ignored like c handler").unwrap()
        );
        assert_eq!("7", MetaMessage::TerminateRequest.to_string());
        assert_eq!("8", MetaMessage::Ping.to_string());
        assert_eq!("9", MetaMessage::Pong.to_string());
    }

    #[test]
    fn parse_tcp_packet_meta_headers() {
        tinc_test_support::assert_can_create_netns();
        let packet = parse_meta_message("17 1500 trailing").unwrap();
        assert_eq!(
            MetaMessage::TcpPacket(TcpPacketMessage { length: 1500 }),
            packet
        );
        assert_eq!("17 1500", packet.to_string());

        let sptps_packet = parse_meta_message("21 64 trailing").unwrap();
        assert_eq!(
            MetaMessage::SptpsTcpPacket(TcpPacketMessage { length: 64 }),
            sptps_packet
        );
        assert_eq!("21 64", sptps_packet.to_string());
    }

    #[test]
    fn parse_key_changed_message() {
        tinc_test_support::assert_can_create_netns();
        let message = parse_meta_message("14 cafebabe alpha ignored").unwrap();

        assert_eq!(
            MetaMessage::KeyChanged(KeyChangedMessage {
                nonce: 0xcafe_babe,
                origin: "alpha".to_owned(),
            }),
            message
        );
        assert_eq!("14 cafebabe alpha", message.to_string());
    }

    #[test]
    fn parse_legacy_and_extended_request_key_messages() {
        tinc_test_support::assert_can_create_netns();
        let legacy = parse_meta_message("15 alpha beta trailing").unwrap();
        assert_eq!(
            MetaMessage::RequestKey(RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: None,
            }),
            legacy
        );
        assert_eq!("15 alpha beta", legacy.to_string());

        let extended = parse_meta_message("15 alpha beta 21 hJ2Y ignored").unwrap();
        assert_eq!(
            MetaMessage::RequestKey(RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: Some(RequestKeyExtension {
                    request: Request::SptpsPacket.number(),
                    payload: Some("hJ2Y".to_owned()),
                }),
            }),
            extended
        );
        assert_eq!("15 alpha beta 21 hJ2Y", extended.to_string());
    }

    #[test]
    fn parse_answer_key_message_with_optional_reflexive_address() {
        tinc_test_support::assert_can_create_netns();
        let answer =
            parse_meta_message("16 alpha beta 4ae0b0a82d6e0078 91 64 4 0 203.0.113.5 655 extra")
                .unwrap();

        assert_eq!(
            MetaMessage::AnswerKey(AnswerKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                key: "4ae0b0a82d6e0078".to_owned(),
                cipher: 91,
                digest: 64,
                mac_length: 4,
                compression: 0,
                address: Some(EdgeAddress {
                    address: "203.0.113.5".to_owned(),
                    port: "655".to_owned(),
                }),
            }),
            answer
        );
        assert_eq!(
            "16 alpha beta 4ae0b0a82d6e0078 91 64 4 0 203.0.113.5 655",
            answer.to_string()
        );
    }

    #[test]
    fn parse_sptps_answer_key_shape_with_negative_algorithms() {
        tinc_test_support::assert_can_create_netns();
        let answer = parse_meta_message("16 alpha beta hJ2Y -1 -1 -1 0").unwrap();

        assert_eq!(
            MetaMessage::AnswerKey(AnswerKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                key: "hJ2Y".to_owned(),
                cipher: -1,
                digest: -1,
                mac_length: u64::MAX,
                compression: 0,
                address: None,
            }),
            answer
        );
    }

    #[test]
    fn parse_udp_and_mtu_info_messages() {
        tinc_test_support::assert_can_create_netns();
        let udp = parse_meta_message("22 alpha beta 203.0.113.10 655 ignored").unwrap();
        assert_eq!(
            MetaMessage::UdpInfo(UdpInfoMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                endpoint: EdgeAddress {
                    address: "203.0.113.10".to_owned(),
                    port: "655".to_owned(),
                },
            }),
            udp
        );
        assert_eq!("22 alpha beta 203.0.113.10 655", udp.to_string());

        let mtu = parse_meta_message("23 alpha beta 1400 trailing").unwrap();
        assert_eq!(
            MetaMessage::MtuInfo(MtuInfoMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                mtu: 1400,
            }),
            mtu
        );
        assert_eq!("23 alpha beta 1400", mtu.to_string());
    }

    #[test]
    fn mtu_info_rejects_too_small_and_clamps_too_large_mtu_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(MetaMessageError::InvalidMtu(511)),
            parse_meta_message("23 alpha beta 511")
        );
        assert_eq!(
            MetaMessage::MtuInfo(MtuInfoMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                mtu: DEFAULT_MTU,
            }),
            parse_meta_message("23 alpha beta 9999").unwrap()
        );
        assert_eq!(
            Err(MetaMessageError::InvalidInteger {
                field: "mtu",
                value: "not-mtu".to_owned(),
            }),
            parse_meta_message("23 alpha beta not-mtu")
        );
    }

    #[test]
    fn request_key_helpers_encode_and_decode_sptps_initial_request_payloads() {
        tinc_test_support::assert_can_create_netns();
        let message = RequestKeyMessage::sptps_initial_request("alpha", "beta", b"abc");

        assert_eq!(
            MetaMessage::RequestKey(message.clone()).to_string(),
            "15 alpha beta 15 hJ2Y"
        );
        assert_eq!(
            SptpsKeyPayload {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                kind: SptpsKeyPayloadKind::InitialRequest,
                data: b"abc".to_vec(),
                compression: None,
                address: None,
            },
            message.decode_sptps_payload().unwrap()
        );
    }

    #[test]
    fn request_key_helpers_encode_and_decode_sptps_tcp_packet_payloads() {
        tinc_test_support::assert_can_create_netns();
        let message = RequestKeyMessage::sptps_tcp_packet("alpha", "beta", b"hello");

        assert_eq!(
            MetaMessage::RequestKey(message.clone()).to_string(),
            "15 alpha beta 21 oVGbs9G"
        );
        assert_eq!(
            SptpsKeyPayloadKind::TcpPacket,
            message.decode_sptps_payload().unwrap().kind
        );
        assert_eq!(b"hello", &message.decode_sptps_payload().unwrap().data[..]);
    }

    #[test]
    fn answer_key_helpers_encode_and_decode_sptps_handshake_payloads() {
        tinc_test_support::assert_can_create_netns();
        let message = AnswerKeyMessage::sptps_handshake("alpha", "beta", b"abc", 12)
            .with_address("203.0.113.5", "655");

        assert_eq!(
            "16 alpha beta hJ2Y -1 -1 18446744073709551615 12 203.0.113.5 655",
            MetaMessage::AnswerKey(message.clone()).to_string()
        );
        assert!(message.is_sptps_handshake());
        assert_eq!(
            SptpsKeyPayload {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                kind: SptpsKeyPayloadKind::HandshakeAnswer,
                data: b"abc".to_vec(),
                compression: Some(12),
                address: Some(EdgeAddress {
                    address: "203.0.113.5".to_owned(),
                    port: "655".to_owned(),
                }),
            },
            message.decode_sptps_payload().unwrap()
        );
    }

    #[test]
    fn sptps_payload_decoders_reject_non_sptps_and_invalid_payloads() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(SptpsKeyPayloadError::NotSptps),
            RequestKeyMessage::new("alpha", "beta").decode_sptps_payload()
        );
        assert_eq!(
            Err(SptpsKeyPayloadError::NotSptps),
            RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: Some(RequestKeyExtension {
                    request: Request::AnswerPublicKey.number(),
                    payload: Some("hJ2Y".to_owned()),
                }),
            }
            .decode_sptps_payload()
        );
        assert_eq!(
            Err(SptpsKeyPayloadError::MissingPayload),
            RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: Some(RequestKeyExtension {
                    request: Request::SptpsPacket.number(),
                    payload: None,
                }),
            }
            .decode_sptps_payload()
        );
        assert!(matches!(
            RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: Some(RequestKeyExtension {
                    request: Request::SptpsPacket.number(),
                    payload: Some("????".to_owned()),
                }),
            }
            .decode_sptps_payload(),
            Err(SptpsKeyPayloadError::InvalidBase64(_))
        ));
        assert_eq!(
            Err(SptpsKeyPayloadError::NotSptps),
            AnswerKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                key: "hJ2Y".to_owned(),
                cipher: 0,
                digest: -1,
                mac_length: u64::MAX,
                compression: 0,
                address: None,
            }
            .decode_sptps_payload()
        );
    }

    #[test]
    fn key_message_parser_rejects_invalid_fields() {
        tinc_test_support::assert_can_create_netns();
        assert!(matches!(
            parse_meta_message("14 1 bad-name"),
            Err(MetaMessageError::InvalidName(_))
        ));
        assert_eq!(
            MetaMessage::RequestKey(RequestKeyMessage {
                from: "alpha".to_owned(),
                to: "beta".to_owned(),
                extension: None,
            }),
            parse_meta_message("15 alpha beta bad").unwrap()
        );
        assert_eq!(
            Err(MetaMessageError::InvalidInteger {
                field: "cipher",
                value: "cipher".to_owned(),
            }),
            parse_meta_message("16 alpha beta key cipher 64 4 0")
        );
        assert_eq!(
            Err(MetaMessageError::MissingField("port")),
            parse_meta_message("16 alpha beta key 1 2 3 4 203.0.113.1")
        );
    }
}

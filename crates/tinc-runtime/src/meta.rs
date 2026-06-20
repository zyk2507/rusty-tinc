// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use tinc_core::graph::{Edge, OPTION_PMTU_DISCOVERY};
use tinc_core::protocol::{
    AckMessage, AddEdgeMessage, EdgeAddress, IdMessage, MetaMessage, MetaMessageError, PROT_MAJOR,
    PROT_MINOR, Request, TcpPacketMessage, parse_meta_message,
};
use tinc_core::state::{NetworkState, StateError, StateMutation};
use tinc_core::utils::check_id;

use crate::sptps::{
    SPTPS_TCP_AUTH_OVERHEAD, SPTPS_TCP_HEADER_LEN, SptpsError, SptpsHandshakeEvent,
    SptpsHandshakeSession, TincEd25519PrivateKey, TincEd25519PublicKey,
};
use crate::transport::MAX_META_BUFFER_SIZE;

pub const SPTPS_META_RECORD: u8 = 0;
// C sptps_receive_data() keeps a separate buffer for one TCP SPTPS record and
// reallocates it to reclen + 19 bytes after reading the u16 record length.
const MAX_SPTPS_TCP_RECORD_BUFFER_SIZE: usize = u16::MAX as usize + SPTPS_TCP_AUTH_OVERHEAD;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionAuth {
    myself: String,
    peer: Option<String>,
    outgoing: bool,
    private_key: TincEd25519PrivateKey,
    peer_key: TincEd25519PublicKey,
    local_port: String,
    local_weight: i32,
    local_options: u32,
    session: Option<SptpsHandshakeSession>,
    state: MetaAuthState,
    bypass_security: bool,
}

impl MetaConnectionAuth {
    pub fn new(
        myself: impl Into<String>,
        outgoing: bool,
        private_key: TincEd25519PrivateKey,
        peer_key: TincEd25519PublicKey,
        local_port: impl Into<String>,
        local_weight: i32,
        local_options: u32,
    ) -> Self {
        Self {
            myself: myself.into(),
            peer: None,
            outgoing,
            private_key,
            peer_key,
            local_port: local_port.into(),
            local_weight,
            local_options,
            session: None,
            state: MetaAuthState::ExpectId,
            bypass_security: false,
        }
    }

    pub fn with_bypass_security(mut self, bypass_security: bool) -> Self {
        self.bypass_security = bypass_security;
        self
    }

    pub fn state(&self) -> MetaAuthState {
        self.state
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    pub fn outgoing(&self) -> bool {
        self.outgoing
    }

    pub fn pending_session(&self) -> Option<&SptpsHandshakeSession> {
        self.session.as_ref()
    }

    pub fn sptps_in_encrypted(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| session.tcp_codec().in_key().is_some())
    }

    pub fn local_id_message(&self) -> MetaMessage {
        MetaMessage::Id(IdMessage {
            name: self.myself.clone(),
            protocol_major: PROT_MAJOR as i32,
            protocol_minor: Some(if self.bypass_security {
                0
            } else {
                PROT_MINOR as i32
            }),
        })
    }

    fn uses_plaintext_meta(&self) -> bool {
        self.bypass_security
            && matches!(
                self.state,
                MetaAuthState::ExpectAck | MetaAuthState::Activated
            )
    }

    pub fn send_sptps_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<Vec<u8>, MetaAuthError> {
        self.send_sptps_application(&encode_meta_line(message))
    }

    pub fn send_sptps_application(&mut self, payload: &[u8]) -> Result<Vec<u8>, MetaAuthError> {
        let session = self.session.as_mut().ok_or(MetaAuthError::MissingSession)?;
        session
            .send_record(SPTPS_META_RECORD, payload)
            .map_err(Into::into)
    }

    pub fn receive_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<MetaAuthStep, MetaAuthError> {
        match message {
            MetaMessage::Id(message) => self.receive_id(message),
            MetaMessage::Ack(message) => self.receive_ack(message),
            message => Err(MetaAuthError::UnexpectedMessage {
                expected: self.state.expected_request(),
                actual: message.request(),
            }),
        }
    }

    pub fn receive_sptps_record(&mut self, record: &[u8]) -> Result<MetaAuthStep, MetaAuthError> {
        if !matches!(
            self.state,
            MetaAuthState::Handshake | MetaAuthState::ExpectAck | MetaAuthState::Activated
        ) {
            return Err(MetaAuthError::UnexpectedRawRecord(self.state));
        }

        let peer = self.peer.clone().ok_or(MetaAuthError::MissingPeer)?;
        let session = self.session.as_mut().ok_or(MetaAuthError::MissingSession)?;
        let events = session.receive_datagram(record)?;
        let mut step = MetaAuthStep::default();
        let completed_handshake = events
            .iter()
            .any(|event| matches!(event, SptpsHandshakeEvent::HandshakeComplete));

        step.raw_outbound.extend(session.drain_outbound());

        if completed_handshake && self.state == MetaAuthState::Handshake {
            step.outbound.push(self.ack_message());
            step.events
                .push(MetaAuthEvent::SptpsHandshakeComplete { peer });
            self.state = MetaAuthState::ExpectAck;
        } else if completed_handshake {
            step.events
                .push(MetaAuthEvent::SptpsHandshakeComplete { peer });
        }

        for event in events {
            if let SptpsHandshakeEvent::ApplicationRecord {
                record_type,
                payload,
            } = event
            {
                step.events.push(MetaAuthEvent::ApplicationRecord {
                    record_type,
                    payload,
                });
            }
        }

        Ok(step)
    }

    fn receive_id(&mut self, message: &IdMessage) -> Result<MetaAuthStep, MetaAuthError> {
        if self.state != MetaAuthState::ExpectId {
            return Err(MetaAuthError::UnexpectedMessage {
                expected: self.state.expected_request(),
                actual: Request::Id,
            });
        }

        validate_peer_id(&self.myself, message)?;

        if message.protocol_major != PROT_MAJOR as i32 {
            return Err(MetaAuthError::IncompatibleProtocol {
                expected: PROT_MAJOR as i32,
                actual: message.protocol_major,
            });
        }

        self.peer = Some(message.name.clone());

        if self.bypass_security {
            self.state = MetaAuthState::ExpectAck;
            return Ok(MetaAuthStep {
                outbound: vec![self.ack_message()],
                ..MetaAuthStep::default()
            });
        }

        let minor = message.protocol_minor.unwrap_or(0);
        if minor < 2 {
            return Err(MetaAuthError::UnsupportedLegacyProtocol(minor));
        }

        let label = sptps_tcp_label(
            if self.outgoing {
                &self.myself
            } else {
                &message.name
            },
            if self.outgoing {
                &message.name
            } else {
                &self.myself
            },
        );
        let mut session = SptpsHandshakeSession::start_tcp(
            self.outgoing,
            self.private_key.clone(),
            self.peer_key,
            label,
        )?;
        let raw_outbound = session.drain_outbound();
        self.session = Some(session);
        self.state = MetaAuthState::Handshake;

        Ok(MetaAuthStep {
            raw_outbound,
            ..MetaAuthStep::default()
        })
    }

    fn receive_ack(&mut self, message: &AckMessage) -> Result<MetaAuthStep, MetaAuthError> {
        if self.state != MetaAuthState::ExpectAck {
            return Err(MetaAuthError::UnexpectedMessage {
                expected: self.state.expected_request(),
                actual: Request::Ack,
            });
        }

        let AckMessage::Connection {
            port,
            weight,
            options,
        } = message
        else {
            return Err(MetaAuthError::UnexpectedAckShape);
        };

        let peer = self.peer.clone().ok_or(MetaAuthError::MissingPeer)?;
        let negotiated_options = negotiated_connection_options(self.local_options, *options);
        self.state = MetaAuthState::Activated;

        Ok(MetaAuthStep {
            events: vec![MetaAuthEvent::Activated {
                peer,
                port: port.clone(),
                weight: negotiated_weight(self.local_weight, *weight),
                options: negotiated_options,
            }],
            ..MetaAuthStep::default()
        })
    }

    fn ack_message(&self) -> MetaMessage {
        MetaMessage::Ack(AckMessage::Connection {
            port: self.local_port.clone(),
            weight: self.local_weight,
            options: self.local_options,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetaStreamDecoder {
    buffer: Vec<u8>,
    pending_body: Option<MetaBodyRequest>,
}

impl MetaStreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn pending_body(&self) -> Option<MetaBodyRequest> {
        self.pending_body
    }

    pub fn push(&mut self, data: &[u8]) -> Result<(), MetaStreamError> {
        self.push_limited(data, MAX_META_BUFFER_SIZE)
    }

    fn push_limited(&mut self, data: &[u8], maximum: usize) -> Result<(), MetaStreamError> {
        let next_len = self.buffer.len().saturating_add(data.len());
        if next_len > maximum {
            return Err(MetaStreamError::InputBufferFull {
                maximum,
                actual: next_len,
            });
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    pub fn observe_meta_message(&mut self, message: &MetaMessage) {
        match message {
            MetaMessage::TcpPacket(message) => {
                self.expect_body(MetaBodyKind::TcpPacket, message.length as usize)
            }
            MetaMessage::SptpsTcpPacket(message) => {
                self.expect_body(MetaBodyKind::SptpsPacket, message.length as usize)
            }
            _ => {}
        }
    }

    pub fn expect_body(&mut self, kind: MetaBodyKind, length: usize) {
        self.pending_body = Some(MetaBodyRequest { kind, length });
    }

    pub fn next_plaintext_frame(&mut self) -> Result<Option<MetaStreamFrame>, MetaStreamError> {
        if let Some(body) = self.next_body_frame() {
            return Ok(Some(body));
        }

        let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let line = self.buffer.drain(..=position).collect::<Vec<_>>();
        Ok(Some(MetaStreamFrame::Line(decode_meta_line(line)?)))
    }

    pub fn next_sptps_frame(
        &mut self,
        encrypted: bool,
    ) -> Result<Option<MetaStreamFrame>, MetaStreamError> {
        if let Some(body) = self.next_body_frame() {
            return Ok(Some(body));
        }

        let Some(expected) = self.expected_sptps_frame_len(encrypted) else {
            return Ok(None);
        };

        if self.buffer.len() < expected {
            return Ok(None);
        }

        Ok(Some(MetaStreamFrame::SptpsRecord(
            self.buffer.drain(..expected).collect(),
        )))
    }

    fn expected_sptps_frame_len(&self, encrypted: bool) -> Option<usize> {
        if self.buffer.len() < 2 {
            return None;
        }

        let length = u16::from_be_bytes(
            self.buffer[..2]
                .try_into()
                .expect("SPTPS TCP length bytes checked"),
        ) as usize;
        Some(
            length
                + if encrypted {
                    SPTPS_TCP_AUTH_OVERHEAD
                } else {
                    SPTPS_TCP_HEADER_LEN
                },
        )
    }

    fn next_body_frame(&mut self) -> Option<MetaStreamFrame> {
        let pending = self.pending_body?;

        if self.buffer.len() < pending.length {
            return None;
        }

        self.pending_body = None;
        Some(MetaStreamFrame::Body {
            kind: pending.kind,
            data: self.buffer.drain(..pending.length).collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetaBodyRequest {
    pub kind: MetaBodyKind,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaBodyKind {
    TcpPacket,
    SptpsPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaStreamFrame {
    Line(String),
    SptpsRecord(Vec<u8>),
    Body { kind: MetaBodyKind, data: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaStreamError {
    InvalidUtf8,
    InputBufferFull { maximum: usize, actual: usize },
}

impl fmt::Display for MetaStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => write!(f, "meta stream line is not valid UTF-8"),
            Self::InputBufferFull { maximum, actual } => {
                write!(
                    f,
                    "meta input buffer full: {actual} bytes, maximum is {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for MetaStreamError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionDriver {
    auth: MetaConnectionAuth,
    decoder: MetaStreamDecoder,
    pending_tcp_packet: Option<usize>,
}

impl MetaConnectionDriver {
    pub fn new(auth: MetaConnectionAuth) -> Self {
        Self {
            auth,
            decoder: MetaStreamDecoder::new(),
            pending_tcp_packet: None,
        }
    }

    pub fn auth(&self) -> &MetaConnectionAuth {
        &self.auth
    }

    pub fn auth_mut(&mut self) -> &mut MetaConnectionAuth {
        &mut self.auth
    }

    pub fn decoder(&self) -> &MetaStreamDecoder {
        &self.decoder
    }

    pub fn pending_tcp_packet(&self) -> Option<usize> {
        self.pending_tcp_packet
    }

    pub fn initial_id_bytes(&self) -> Vec<u8> {
        encode_meta_line(&self.auth.local_id_message())
    }

    pub fn receive_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<MetaConnectionStep, MetaConnectionError> {
        let mut step = MetaConnectionStep::default();
        let mut remaining = data;

        self.drain_available_frames(&mut step)?;
        while !remaining.is_empty() {
            let (limit, available) = self.next_input_window()?;
            if available == 0 {
                return Err(MetaStreamError::InputBufferFull {
                    maximum: limit,
                    actual: self.decoder.buffered_len().saturating_add(remaining.len()),
                }
                .into());
            }
            let take = remaining.len().min(available);
            self.decoder.push_limited(&remaining[..take], limit)?;
            remaining = &remaining[take..];
            self.drain_available_frames(&mut step)?;
        }

        Ok(step)
    }

    pub fn send_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<Vec<u8>, MetaConnectionError> {
        if message.request() == Request::Id || self.auth.uses_plaintext_meta() {
            return Ok(encode_meta_line(message));
        }

        self.auth
            .send_sptps_meta_message(message)
            .map_err(MetaConnectionError::Auth)
    }

    pub fn send_tcp_packet(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, MetaConnectionError> {
        self.ensure_activated()?;
        let length = checked_tcp_packet_length(packet.len())?;
        let header = MetaMessage::TcpPacket(TcpPacketMessage { length });
        let header = self.send_meta_message(&header)?;
        if self.auth.uses_plaintext_meta() {
            return Ok(vec![header, packet.to_vec()]);
        }
        let body = self
            .auth
            .send_sptps_application(packet)
            .map_err(MetaConnectionError::Auth)?;

        Ok(vec![header, body])
    }

    pub fn send_sptps_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<Vec<u8>>, MetaConnectionError> {
        self.ensure_activated()?;
        let length = checked_tcp_packet_length(packet.len())?;
        let header = MetaMessage::SptpsTcpPacket(TcpPacketMessage { length });

        Ok(vec![self.send_meta_message(&header)?, packet.to_vec()])
    }

    fn ensure_activated(&self) -> Result<(), MetaConnectionError> {
        if self.auth.state() == MetaAuthState::Activated {
            Ok(())
        } else {
            Err(MetaConnectionError::NotActivated(self.auth.state()))
        }
    }

    fn drain_available_frames(
        &mut self,
        step: &mut MetaConnectionStep,
    ) -> Result<(), MetaConnectionError> {
        loop {
            let frame = match self.auth.state() {
                MetaAuthState::ExpectId => self.decoder.next_plaintext_frame()?,
                _ if self.auth.uses_plaintext_meta() => self.decoder.next_plaintext_frame()?,
                _ => self
                    .decoder
                    .next_sptps_frame(self.auth.sptps_in_encrypted())?,
            };

            let Some(frame) = frame else {
                break;
            };

            self.handle_frame(frame, step)?;
        }

        Ok(())
    }

    fn next_input_window(&self) -> Result<(usize, usize), MetaConnectionError> {
        if let Some(body) = self.decoder.pending_body() {
            if body.length > MAX_META_BUFFER_SIZE {
                return Err(MetaStreamError::InputBufferFull {
                    maximum: MAX_META_BUFFER_SIZE,
                    actual: body.length,
                }
                .into());
            }
            return Ok((
                MAX_META_BUFFER_SIZE,
                body.length.saturating_sub(self.decoder.buffered_len()),
            ));
        }

        if matches!(self.auth.state(), MetaAuthState::ExpectId) || self.auth.uses_plaintext_meta() {
            return Ok((
                MAX_META_BUFFER_SIZE,
                MAX_META_BUFFER_SIZE.saturating_sub(self.decoder.buffered_len()),
            ));
        }

        if self.decoder.buffered_len() < 2 {
            return Ok((
                MAX_SPTPS_TCP_RECORD_BUFFER_SIZE,
                2 - self.decoder.buffered_len(),
            ));
        }

        let expected = self
            .decoder
            .expected_sptps_frame_len(self.auth.sptps_in_encrypted())
            .expect("SPTPS TCP length bytes checked");
        Ok((
            MAX_SPTPS_TCP_RECORD_BUFFER_SIZE,
            expected.saturating_sub(self.decoder.buffered_len()),
        ))
    }

    fn handle_frame(
        &mut self,
        frame: MetaStreamFrame,
        step: &mut MetaConnectionStep,
    ) -> Result<(), MetaConnectionError> {
        match frame {
            MetaStreamFrame::Line(line) => {
                self.handle_meta_line(&line, MetaLineSource::Plaintext, step)
            }
            MetaStreamFrame::SptpsRecord(record) => {
                let auth_step = self.auth.receive_sptps_record(&record)?;
                self.apply_auth_step(auth_step, step)
            }
            MetaStreamFrame::Body { kind, data } => match kind {
                MetaBodyKind::TcpPacket => {
                    step.events.push(MetaConnectionEvent::TcpPacket(data));
                    Ok(())
                }
                MetaBodyKind::SptpsPacket => {
                    step.events.push(MetaConnectionEvent::SptpsPacket(data));
                    Ok(())
                }
            },
        }
    }

    fn apply_auth_step(
        &mut self,
        auth_step: MetaAuthStep,
        step: &mut MetaConnectionStep,
    ) -> Result<(), MetaConnectionError> {
        step.outbound.extend(auth_step.raw_outbound);

        for message in auth_step.outbound {
            let encoded = if self.auth.uses_plaintext_meta() {
                encode_meta_line(&message)
            } else {
                self.auth
                    .send_sptps_meta_message(&message)
                    .map_err(MetaConnectionError::Auth)?
            };
            step.outbound.push(encoded);
        }

        for event in auth_step.events {
            match event {
                MetaAuthEvent::ApplicationRecord {
                    record_type,
                    payload,
                } => self.handle_sptps_application(record_type, payload, step)?,
                event => step.events.push(MetaConnectionEvent::Auth(event)),
            }
        }

        Ok(())
    }

    fn handle_sptps_application(
        &mut self,
        record_type: u8,
        payload: Vec<u8>,
        step: &mut MetaConnectionStep,
    ) -> Result<(), MetaConnectionError> {
        if record_type != SPTPS_META_RECORD {
            step.events.push(MetaConnectionEvent::ApplicationRecord {
                record_type,
                payload,
            });
            return Ok(());
        }

        if let Some(expected) = self.pending_tcp_packet.take() {
            let actual = payload.len();

            if actual != expected {
                return Err(MetaConnectionError::PacketLengthMismatch { expected, actual });
            }

            step.events.push(MetaConnectionEvent::TcpPacket(payload));
            return Ok(());
        }

        let line = decode_meta_line(payload)?;
        self.handle_meta_line(&line, MetaLineSource::SptpsApplication, step)
    }

    fn handle_meta_line(
        &mut self,
        line: &str,
        source: MetaLineSource,
        step: &mut MetaConnectionStep,
    ) -> Result<(), MetaConnectionError> {
        let message = parse_meta_message(line)?;
        step.events
            .push(MetaConnectionEvent::Message(message.clone()));

        if self.auth.state() != MetaAuthState::Activated {
            let auth_step = self.auth.receive_meta_message(&message)?;
            return self.apply_auth_step(auth_step, step);
        }

        match source {
            MetaLineSource::Plaintext => self.decoder.observe_meta_message(&message),
            MetaLineSource::SptpsApplication => match &message {
                MetaMessage::TcpPacket(message) => {
                    self.pending_tcp_packet = Some(message.length as usize);
                }
                MetaMessage::SptpsTcpPacket(message) => self
                    .decoder
                    .expect_body(MetaBodyKind::SptpsPacket, message.length as usize),
                _ => {}
            },
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetaConnectionStep {
    pub outbound: Vec<Vec<u8>>,
    pub events: Vec<MetaConnectionEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaConnectionEvent {
    Message(MetaMessage),
    Auth(MetaAuthEvent),
    ApplicationRecord { record_type: u8, payload: Vec<u8> },
    TcpPacket(Vec<u8>),
    SptpsPacket(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaConnectionError {
    Stream(MetaStreamError),
    Parse(MetaMessageError),
    Auth(MetaAuthError),
    NotActivated(MetaAuthState),
    PacketTooLarge { maximum: usize, actual: usize },
    PacketLengthMismatch { expected: usize, actual: usize },
}

impl fmt::Display for MetaConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::Auth(error) => write!(f, "{error}"),
            Self::NotActivated(state) => {
                write!(
                    f,
                    "meta connection is not activated, current state is {state:?}"
                )
            }
            Self::PacketTooLarge { maximum, actual } => {
                write!(
                    f,
                    "TCP packet is too large: {actual} bytes, maximum is {maximum}"
                )
            }
            Self::PacketLengthMismatch { expected, actual } => write!(
                f,
                "TCP packet length mismatch: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for MetaConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Auth(error) => Some(error),
            Self::NotActivated(_)
            | Self::PacketTooLarge { .. }
            | Self::PacketLengthMismatch { .. } => None,
        }
    }
}

impl From<MetaStreamError> for MetaConnectionError {
    fn from(error: MetaStreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<MetaMessageError> for MetaConnectionError {
    fn from(error: MetaMessageError) -> Self {
        Self::Parse(error)
    }
}

impl From<MetaAuthError> for MetaConnectionError {
    fn from(error: MetaAuthError) -> Self {
        Self::Auth(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetaLineSource {
    Plaintext,
    SptpsApplication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaAuthState {
    ExpectId,
    Handshake,
    ExpectAck,
    Activated,
}

impl MetaAuthState {
    const fn expected_request(self) -> Option<Request> {
        match self {
            Self::ExpectId => Some(Request::Id),
            Self::Handshake => Some(Request::SptpsPacket),
            Self::ExpectAck => Some(Request::Ack),
            Self::Activated => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetaAuthStep {
    pub outbound: Vec<MetaMessage>,
    pub raw_outbound: Vec<Vec<u8>>,
    pub events: Vec<MetaAuthEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaAuthEvent {
    SptpsHandshakeComplete {
        peer: String,
    },
    Activated {
        peer: String,
        port: String,
        weight: i32,
        options: u32,
    },
    LegacyEd25519Upgrade {
        peer: String,
        public_key: String,
    },
    ApplicationRecord {
        record_type: u8,
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionEdge {
    pub peer: String,
    pub address: String,
    pub port: String,
    pub local: Option<EdgeAddress>,
    pub weight: i32,
    pub options: u32,
    pub nonce: u32,
}

impl MetaConnectionEdge {
    pub fn from_activated_event(
        event: &MetaAuthEvent,
        address: impl Into<String>,
        local: Option<EdgeAddress>,
        nonce: u32,
    ) -> Option<Self> {
        let MetaAuthEvent::Activated {
            peer,
            port,
            weight,
            options,
        } = event
        else {
            return None;
        };

        Some(Self {
            peer: peer.clone(),
            address: address.into(),
            port: port.clone(),
            local,
            weight: *weight,
            options: *options,
            nonce,
        })
    }

    pub fn add_edge_message(&self, myself: &str) -> AddEdgeMessage {
        AddEdgeMessage {
            nonce: self.nonce,
            edge: Edge::new(myself, &self.peer, self.weight).with_options(self.options),
            address: self.address.clone(),
            port: self.port.clone(),
            local: self.local.clone(),
        }
    }

    pub fn apply(self, state: &mut NetworkState) -> Result<StateMutation, StateError> {
        state.apply_meta_message(MetaMessage::AddEdge(
            self.add_edge_message(state.graph.myself()),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaAuthError {
    InvalidPeerName(String),
    SelfConnection(String),
    IncompatibleProtocol {
        expected: i32,
        actual: i32,
    },
    UnsupportedLegacyProtocol(i32),
    UnexpectedMessage {
        expected: Option<Request>,
        actual: Request,
    },
    UnexpectedRawRecord(MetaAuthState),
    UnexpectedAckShape,
    MissingPeer,
    MissingSession,
    Sptps(SptpsError),
}

impl fmt::Display for MetaAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerName(name) => write!(f, "invalid peer name {name}"),
            Self::SelfConnection(name) => write!(f, "peer name {name} is myself"),
            Self::IncompatibleProtocol { expected, actual } => {
                write!(
                    f,
                    "incompatible protocol major {actual}, expected {expected}"
                )
            }
            Self::UnsupportedLegacyProtocol(minor) => {
                write!(f, "legacy meta protocol minor {minor} is not supported")
            }
            Self::UnexpectedMessage { expected, actual } => write!(
                f,
                "unexpected meta auth message {}, expected {}",
                actual.name(),
                expected.map(Request::name).unwrap_or("no more messages")
            ),
            Self::UnexpectedRawRecord(state) => {
                write!(f, "unexpected raw SPTPS record in state {state:?}")
            }
            Self::UnexpectedAckShape => write!(f, "unexpected ACK shape for meta auth"),
            Self::MissingPeer => write!(f, "missing meta auth peer"),
            Self::MissingSession => write!(f, "missing meta auth SPTPS session"),
            Self::Sptps(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MetaAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sptps(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SptpsError> for MetaAuthError {
    fn from(error: SptpsError) -> Self {
        Self::Sptps(error)
    }
}

pub fn sptps_tcp_label(initiator: &str, responder: &str) -> Vec<u8> {
    let mut label = format!("tinc TCP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    label
}

fn negotiated_connection_options(local_options: u32, remote_options: u32) -> u32 {
    let mut local = local_options;
    let mut remote = remote_options;

    if local & remote & OPTION_PMTU_DISCOVERY == 0 {
        local &= !OPTION_PMTU_DISCOVERY;
        remote &= !OPTION_PMTU_DISCOVERY;
    }

    local | remote
}

fn negotiated_weight(local_weight: i32, remote_weight: i32) -> i32 {
    (local_weight + remote_weight) / 2
}

fn encode_meta_line(message: &MetaMessage) -> Vec<u8> {
    let mut line = message.to_string().into_bytes();
    line.push(b'\n');
    line
}

fn checked_tcp_packet_length(length: usize) -> Result<u16, MetaConnectionError> {
    let maximum = i16::MAX as usize;

    if length > maximum {
        return Err(MetaConnectionError::PacketTooLarge {
            maximum,
            actual: length,
        });
    }

    Ok(length as u16)
}

fn decode_meta_line(mut line: Vec<u8>) -> Result<String, MetaStreamError> {
    if line.last() == Some(&b'\n') {
        line.pop();
    }

    if line.last() == Some(&b'\r') {
        line.pop();
    }

    String::from_utf8(line).map_err(|_| MetaStreamError::InvalidUtf8)
}

fn validate_peer_id(myself: &str, message: &IdMessage) -> Result<(), MetaAuthError> {
    if !check_id(&message.name) {
        return Err(MetaAuthError::InvalidPeerName(message.name.clone()));
    }

    if message.name == myself {
        return Err(MetaAuthError::SelfConnection(message.name.clone()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tinc_core::graph::{EdgeEndpoint, OPTION_CLAMP_MSS};
    use tinc_core::protocol::{IdMessage, PROT_MINOR, parse_meta_message};

    use crate::device::MTU;
    use crate::sptps::{
        ED25519_SEED_LEN, SPTPS_HANDSHAKE, SPTPS_TAG_LEN, SptpsKey, SptpsTcpCodec,
        TincEd25519PrivateKey,
    };

    use super::*;

    fn key(byte: u8) -> TincEd25519PrivateKey {
        TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
    }

    fn sptps_key(byte: u8) -> SptpsKey {
        SptpsKey::new([byte; 64])
    }

    fn auth_pair() -> (MetaConnectionAuth, MetaConnectionAuth) {
        let alice_key = key(1);
        let bob_key = key(2);
        (
            MetaConnectionAuth::new(
                "alice",
                true,
                alice_key.clone(),
                bob_key.public_key(),
                "655",
                10,
                (PROT_MINOR as u32) << 24,
            ),
            MetaConnectionAuth::new(
                "bob",
                false,
                bob_key,
                alice_key.public_key(),
                "655",
                20,
                (PROT_MINOR as u32) << 24,
            ),
        )
    }

    fn id(name: &str) -> MetaMessage {
        MetaMessage::Id(IdMessage {
            name: name.to_owned(),
            protocol_major: PROT_MAJOR as i32,
            protocol_minor: Some(PROT_MINOR as i32),
        })
    }

    fn flatten_outbound(outbound: Vec<Vec<u8>>) -> Vec<u8> {
        outbound.into_iter().flatten().collect()
    }

    fn established_driver_pair() -> (MetaConnectionDriver, MetaConnectionDriver) {
        let (alice_auth, bob_auth) = auth_pair();
        let mut alice = MetaConnectionDriver::new(alice_auth);
        let mut bob = MetaConnectionDriver::new(bob_auth);

        let alice_id = alice.initial_id_bytes();
        let bob_after_id = bob.receive_bytes(&alice_id).unwrap();

        let mut bob_to_alice = bob.initial_id_bytes();
        bob_to_alice.extend(flatten_outbound(bob_after_id.outbound));
        let alice_after_bob = alice.receive_bytes(&bob_to_alice).unwrap();

        let bob_after_alice = bob
            .receive_bytes(&flatten_outbound(alice_after_bob.outbound))
            .unwrap();
        let alice_after_bob = alice
            .receive_bytes(&flatten_outbound(bob_after_alice.outbound))
            .unwrap();
        let bob_done = bob
            .receive_bytes(&flatten_outbound(alice_after_bob.outbound))
            .unwrap();

        assert_eq!(MetaAuthState::Activated, alice.auth().state());
        assert_eq!(MetaAuthState::Activated, bob.auth().state());
        assert!(matches!(
            bob_done.events.as_slice(),
            [
                MetaConnectionEvent::Message(MetaMessage::Ack(_)),
                MetaConnectionEvent::Auth(MetaAuthEvent::Activated { .. })
            ]
        ));

        (alice, bob)
    }

    #[test]
    fn bypass_security_uses_plaintext_id_ack_and_meta_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let alice_key = key(1);
        let bob_key = key(2);
        let mut alice = MetaConnectionDriver::new(
            MetaConnectionAuth::new(
                "alice",
                true,
                alice_key.clone(),
                bob_key.public_key(),
                "655",
                10,
                (PROT_MINOR as u32) << 24,
            )
            .with_bypass_security(true),
        );
        let mut bob = MetaConnectionDriver::new(
            MetaConnectionAuth::new(
                "bob",
                false,
                bob_key,
                alice_key.public_key(),
                "655",
                20,
                (PROT_MINOR as u32) << 24,
            )
            .with_bypass_security(true),
        );

        let alice_id = alice.initial_id_bytes();
        assert_eq!(
            "0 alice 17.0\n",
            String::from_utf8(alice_id.clone()).unwrap()
        );
        let bob_after_id = bob.receive_bytes(&alice_id).unwrap();
        assert_eq!(MetaAuthState::ExpectAck, bob.auth().state());
        assert_eq!(
            encode_meta_line(&MetaMessage::Ack(AckMessage::Connection {
                port: "655".to_owned(),
                weight: 20,
                options: (PROT_MINOR as u32) << 24,
            })),
            flatten_outbound(bob_after_id.outbound.clone())
        );

        let mut bob_to_alice = bob.initial_id_bytes();
        assert_eq!(
            "0 bob 17.0\n",
            String::from_utf8(bob_to_alice.clone()).unwrap()
        );
        bob_to_alice.extend(flatten_outbound(bob_after_id.outbound));
        let alice_after_bob = alice.receive_bytes(&bob_to_alice).unwrap();
        assert_eq!(MetaAuthState::Activated, alice.auth().state());
        assert!(matches!(
            alice_after_bob.events.as_slice(),
            [
                MetaConnectionEvent::Message(MetaMessage::Id(_)),
                MetaConnectionEvent::Message(MetaMessage::Ack(_)),
                MetaConnectionEvent::Auth(MetaAuthEvent::Activated { .. }),
            ]
        ));

        let bob_done = bob
            .receive_bytes(&flatten_outbound(alice_after_bob.outbound))
            .unwrap();
        assert_eq!(MetaAuthState::Activated, bob.auth().state());
        assert!(matches!(
            bob_done.events.as_slice(),
            [
                MetaConnectionEvent::Message(MetaMessage::Ack(_)),
                MetaConnectionEvent::Auth(MetaAuthEvent::Activated { .. }),
            ]
        ));

        assert_eq!(
            encode_meta_line(&MetaMessage::Ping),
            alice.send_meta_message(&MetaMessage::Ping).unwrap()
        );
        assert_eq!(
            vec![
                encode_meta_line(&MetaMessage::TcpPacket(TcpPacketMessage { length: 4 })),
                b"pong".to_vec()
            ],
            alice.send_tcp_packet(b"pong").unwrap()
        );
    }

    #[test]
    fn sptps_tcp_label_matches_tinc_null_terminated_label() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            b"tinc TCP key expansion alice bob\0".to_vec(),
            sptps_tcp_label("alice", "bob")
        );
    }

    #[test]
    fn meta_stream_decodes_split_plaintext_lines_and_packet_bodies() {
        tinc_test_support::assert_can_create_netns();
        let mut decoder = MetaStreamDecoder::new();

        decoder.push(b"8\r").unwrap();
        assert_eq!(None, decoder.next_plaintext_frame().unwrap());
        decoder.push(b"\n17 4\nabcd9\n").unwrap();

        assert_eq!(
            Some(MetaStreamFrame::Line("8".to_owned())),
            decoder.next_plaintext_frame().unwrap()
        );

        let line = decoder.next_plaintext_frame().unwrap().unwrap();
        assert_eq!(MetaStreamFrame::Line("17 4".to_owned()), line);
        let MetaStreamFrame::Line(line) = line else {
            panic!("expected meta line");
        };
        decoder.observe_meta_message(&parse_meta_message(&line).unwrap());

        assert_eq!(
            Some(MetaStreamFrame::Body {
                kind: MetaBodyKind::TcpPacket,
                data: b"abcd".to_vec(),
            }),
            decoder.next_plaintext_frame().unwrap()
        );
        assert_eq!(
            Some(MetaStreamFrame::Line("9".to_owned())),
            decoder.next_plaintext_frame().unwrap()
        );
        assert_eq!(0, decoder.buffered_len());
    }

    #[test]
    fn meta_stream_decodes_plain_and_encrypted_sptps_records() {
        tinc_test_support::assert_can_create_netns();
        let mut plain_codec = SptpsTcpCodec::new();
        let plain_record = plain_codec.encode(SPTPS_HANDSHAKE, b"kex").unwrap();
        let mut decoder = MetaStreamDecoder::new();

        decoder.push(&plain_record[..2]).unwrap();
        assert_eq!(None, decoder.next_sptps_frame(false).unwrap());
        decoder.push(&plain_record[2..]).unwrap();
        assert_eq!(
            Some(MetaStreamFrame::SptpsRecord(plain_record)),
            decoder.next_sptps_frame(false).unwrap()
        );

        let key = sptps_key(7);
        let mut encrypted_codec = SptpsTcpCodec::with_keys(key.clone(), key);
        let encrypted_record = encrypted_codec.encode(0, b"8\n").unwrap();
        assert_eq!(2 + 1 + 2 + SPTPS_TAG_LEN, encrypted_record.len());
        decoder
            .push(&encrypted_record[..encrypted_record.len() - 1])
            .unwrap();
        assert_eq!(None, decoder.next_sptps_frame(true).unwrap());
        decoder
            .push(&encrypted_record[encrypted_record.len() - 1..])
            .unwrap();
        assert_eq!(
            Some(MetaStreamFrame::SptpsRecord(encrypted_record)),
            decoder.next_sptps_frame(true).unwrap()
        );
    }

    #[test]
    fn meta_stream_returns_raw_sptps_packet_body_before_next_record() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = SptpsTcpCodec::new();
        let record = codec.encode(SPTPS_HANDSHAKE, b"kex").unwrap();
        let mut decoder = MetaStreamDecoder::new();

        decoder.expect_body(MetaBodyKind::SptpsPacket, 3);
        decoder.push(b"abc").unwrap();
        decoder.push(&record).unwrap();

        assert_eq!(
            Some(MetaStreamFrame::Body {
                kind: MetaBodyKind::SptpsPacket,
                data: b"abc".to_vec(),
            }),
            decoder.next_sptps_frame(false).unwrap()
        );
        assert_eq!(
            Some(MetaStreamFrame::SptpsRecord(record)),
            decoder.next_sptps_frame(false).unwrap()
        );
    }

    #[test]
    fn meta_connection_driver_completes_modern_handshake_from_tcp_bytes() {
        tinc_test_support::assert_can_create_netns();
        let (alice_auth, bob_auth) = auth_pair();
        let mut alice = MetaConnectionDriver::new(alice_auth);
        let mut bob = MetaConnectionDriver::new(bob_auth);

        let alice_id = alice.initial_id_bytes();
        let bob_after_id = bob.receive_bytes(&alice_id).unwrap();
        assert_eq!(MetaAuthState::Handshake, bob.auth().state());
        assert_eq!(1, bob_after_id.outbound.len());

        let mut bob_to_alice = bob.initial_id_bytes();
        bob_to_alice.extend(flatten_outbound(bob_after_id.outbound));
        let alice_after_bob = alice.receive_bytes(&bob_to_alice).unwrap();
        assert_eq!(MetaAuthState::Handshake, alice.auth().state());
        assert_eq!(2, alice_after_bob.outbound.len());

        let bob_after_alice = bob
            .receive_bytes(&flatten_outbound(alice_after_bob.outbound))
            .unwrap();
        assert_eq!(MetaAuthState::ExpectAck, bob.auth().state());
        assert_eq!(2, bob_after_alice.outbound.len());
        assert!(bob_after_alice.events.contains(&MetaConnectionEvent::Auth(
            MetaAuthEvent::SptpsHandshakeComplete {
                peer: "alice".to_owned(),
            }
        )));

        let alice_after_bob = alice
            .receive_bytes(&flatten_outbound(bob_after_alice.outbound))
            .unwrap();
        assert_eq!(MetaAuthState::Activated, alice.auth().state());
        assert_eq!(1, alice_after_bob.outbound.len());
        assert!(alice_after_bob.events.contains(&MetaConnectionEvent::Auth(
            MetaAuthEvent::Activated {
                peer: "bob".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: (PROT_MINOR as u32) << 24,
            }
        )));

        let bob_done = bob
            .receive_bytes(&flatten_outbound(alice_after_bob.outbound))
            .unwrap();
        assert_eq!(MetaAuthState::Activated, bob.auth().state());
        assert!(
            bob_done
                .events
                .contains(&MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                    peer: "alice".to_owned(),
                    port: "655".to_owned(),
                    weight: 15,
                    options: (PROT_MINOR as u32) << 24,
                }))
        );
    }

    #[test]
    fn meta_connection_driver_separates_tcp_and_sptps_packet_bodies() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, mut bob) = established_driver_pair();

        let tcp_bytes = flatten_outbound(alice.send_tcp_packet(b"abcd").unwrap());
        let tcp_step = bob.receive_bytes(&tcp_bytes).unwrap();
        assert_eq!(
            vec![
                MetaConnectionEvent::Message(MetaMessage::TcpPacket(TcpPacketMessage {
                    length: 4
                })),
                MetaConnectionEvent::TcpPacket(b"abcd".to_vec()),
            ],
            tcp_step.events
        );

        let sptps_bytes = flatten_outbound(alice.send_sptps_packet(b"raw").unwrap());
        let sptps_step = bob.receive_bytes(&sptps_bytes).unwrap();
        assert_eq!(
            vec![
                MetaConnectionEvent::Message(MetaMessage::SptpsTcpPacket(TcpPacketMessage {
                    length: 3
                })),
                MetaConnectionEvent::SptpsPacket(b"raw".to_vec()),
            ],
            sptps_step.events
        );
    }

    #[test]
    fn meta_connection_driver_drains_frames_while_receiving_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, mut bob) = established_driver_pair();
        let packet = vec![0x5a; MTU];
        let mut combined = Vec::new();

        combined.extend(flatten_outbound(alice.send_sptps_packet(&packet).unwrap()));
        combined.extend(flatten_outbound(alice.send_sptps_packet(&packet).unwrap()));
        assert!(
            combined.len() > MAX_META_BUFFER_SIZE,
            "test input must exceed one tinc MAXBUFSIZE-sized read buffer"
        );

        let step = bob.receive_bytes(&combined).unwrap();
        assert_eq!(
            vec![
                MetaConnectionEvent::Message(MetaMessage::SptpsTcpPacket(TcpPacketMessage {
                    length: MTU as u16
                })),
                MetaConnectionEvent::SptpsPacket(packet.clone()),
                MetaConnectionEvent::Message(MetaMessage::SptpsTcpPacket(TcpPacketMessage {
                    length: MTU as u16
                })),
                MetaConnectionEvent::SptpsPacket(packet),
            ],
            step.events
        );
    }

    #[test]
    fn meta_auth_drives_modern_sptps_tcp_handshake_and_ack_activation() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, mut bob) = auth_pair();

        let alice_kex = alice.receive_meta_message(&id("bob")).unwrap();
        assert_eq!(MetaAuthState::Handshake, alice.state());
        assert_eq!(1, alice_kex.raw_outbound.len());

        let bob_kex = bob.receive_meta_message(&id("alice")).unwrap();
        assert_eq!(MetaAuthState::Handshake, bob.state());
        assert_eq!(1, bob_kex.raw_outbound.len());

        let bob_after_alice_kex = bob
            .receive_sptps_record(&alice_kex.raw_outbound[0])
            .unwrap();
        assert!(bob_after_alice_kex.raw_outbound.is_empty());
        assert!(bob_after_alice_kex.outbound.is_empty());

        let alice_sig = alice
            .receive_sptps_record(&bob_kex.raw_outbound[0])
            .unwrap();
        assert_eq!(1, alice_sig.raw_outbound.len());
        assert!(alice_sig.outbound.is_empty());

        let bob_ack = bob
            .receive_sptps_record(&alice_sig.raw_outbound[0])
            .unwrap();
        assert_eq!(MetaAuthState::ExpectAck, bob.state());
        assert_eq!(
            vec![MetaAuthEvent::SptpsHandshakeComplete {
                peer: "alice".to_owned()
            }],
            bob_ack.events
        );
        assert_eq!(
            vec![MetaMessage::Ack(AckMessage::Connection {
                port: "655".to_owned(),
                weight: 20,
                options: (PROT_MINOR as u32) << 24,
            })],
            bob_ack.outbound
        );

        assert_eq!(1, bob_ack.raw_outbound.len());
        let alice_ack = alice
            .receive_sptps_record(&bob_ack.raw_outbound[0])
            .unwrap();
        assert_eq!(MetaAuthState::ExpectAck, alice.state());
        assert_eq!(
            vec![MetaMessage::Ack(AckMessage::Connection {
                port: "655".to_owned(),
                weight: 10,
                options: (PROT_MINOR as u32) << 24,
            })],
            alice_ack.outbound
        );

        let alice_done = alice.receive_meta_message(&bob_ack.outbound[0]).unwrap();
        assert_eq!(
            vec![MetaAuthEvent::Activated {
                peer: "bob".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: (PROT_MINOR as u32) << 24,
            }],
            alice_done.events
        );
        assert_eq!(MetaAuthState::Activated, alice.state());

        let bob_done = bob.receive_meta_message(&alice_ack.outbound[0]).unwrap();
        assert_eq!(
            vec![MetaAuthEvent::Activated {
                peer: "alice".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: (PROT_MINOR as u32) << 24,
            }],
            bob_done.events
        );
        assert_eq!(MetaAuthState::Activated, bob.state());
    }

    #[test]
    fn activated_event_can_create_direct_edge_in_network_state() {
        tinc_test_support::assert_can_create_netns();
        let event = MetaAuthEvent::Activated {
            peer: "bob".to_owned(),
            port: "655".to_owned(),
            weight: 15,
            options: OPTION_CLAMP_MSS | ((PROT_MINOR as u32) << 24),
        };
        let edge = MetaConnectionEdge::from_activated_event(
            &event,
            "203.0.113.10",
            Some(EdgeAddress {
                address: "192.0.2.1".to_owned(),
                port: "655".to_owned(),
            }),
            0xfeed,
        )
        .unwrap();
        let mut state = NetworkState::new("alice");
        let mutation = edge.apply(&mut state).unwrap();

        let StateMutation::AddEdge {
            edge, reachability, ..
        } = mutation
        else {
            panic!("expected ADD_EDGE mutation");
        };
        assert_eq!(tinc_core::graph::EdgeMutation::Inserted, edge);
        assert!(!reachability.became_reachable.contains(&"bob".to_owned()));

        let stored = state.graph.edge("alice", "bob").unwrap();
        assert_eq!(
            Some(&EdgeEndpoint::new("203.0.113.10", "655")),
            stored.address.as_ref()
        );
        assert_eq!(
            Some(&EdgeEndpoint::new("192.0.2.1", "655")),
            stored.local_address.as_ref()
        );
        assert_eq!(15, stored.weight);
        assert_eq!(
            OPTION_CLAMP_MSS | ((PROT_MINOR as u32) << 24),
            stored.options
        );
    }

    #[test]
    fn ack_activation_negotiates_weight_and_pmtu_option_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(15, negotiated_weight(10, 20));
        assert_eq!(
            OPTION_CLAMP_MSS,
            negotiated_connection_options(
                OPTION_CLAMP_MSS | OPTION_PMTU_DISCOVERY,
                OPTION_CLAMP_MSS
            )
        );
        assert_eq!(
            OPTION_CLAMP_MSS | OPTION_PMTU_DISCOVERY,
            negotiated_connection_options(
                OPTION_CLAMP_MSS | OPTION_PMTU_DISCOVERY,
                OPTION_CLAMP_MSS | OPTION_PMTU_DISCOVERY
            )
        );
    }

    #[test]
    fn meta_auth_rejects_bad_id_and_legacy_minor() {
        tinc_test_support::assert_can_create_netns();
        let (mut auth, _) = auth_pair();
        assert_eq!(
            Err(MetaAuthError::InvalidPeerName("bad-name".to_owned())),
            auth.receive_meta_message(&MetaMessage::Id(IdMessage {
                name: "bad-name".to_owned(),
                protocol_major: PROT_MAJOR as i32,
                protocol_minor: Some(PROT_MINOR as i32),
            }))
        );
        assert_eq!(
            Err(MetaAuthError::SelfConnection("alice".to_owned())),
            auth.receive_meta_message(&id("alice"))
        );
        assert_eq!(
            Err(MetaAuthError::UnsupportedLegacyProtocol(1)),
            auth.receive_meta_message(&MetaMessage::Id(IdMessage {
                name: "bob".to_owned(),
                protocol_major: PROT_MAJOR as i32,
                protocol_minor: Some(1),
            }))
        );
    }
}

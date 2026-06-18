// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::BTreeMap;
use std::fmt;

use tinc_core::protocol::{
    AnswerKeyMessage, MetaMessage, Request, RequestKeyMessage, SptpsKeyPayload,
    SptpsKeyPayloadError, SptpsKeyPayloadKind,
};

use crate::sptps::{
    DEFAULT_SPTPS_REPLAY_WINDOW_BYTES, SPTPS_HANDSHAKE, SptpsError, SptpsHandshakeEvent,
    SptpsHandshakeSession, TincEd25519PrivateKey, TincEd25519PublicKey,
};
use crate::transport::SptpsPeerSession;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsKeyExchange {
    myself: String,
    private_key: TincEd25519PrivateKey,
    peer_keys: BTreeMap<String, TincEd25519PublicKey>,
    sessions: BTreeMap<String, SptpsHandshakeSession>,
    compression: i32,
    packet_type: u8,
    replay_window_bytes: usize,
}

impl SptpsKeyExchange {
    pub fn new(
        myself: impl Into<String>,
        private_key: TincEd25519PrivateKey,
        packet_type: u8,
    ) -> Result<Self, SptpsKeyExchangeError> {
        if packet_type >= SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(packet_type).into());
        }

        Ok(Self {
            myself: myself.into(),
            private_key,
            peer_keys: BTreeMap::new(),
            sessions: BTreeMap::new(),
            compression: 0,
            packet_type,
            replay_window_bytes: DEFAULT_SPTPS_REPLAY_WINDOW_BYTES,
        })
    }

    pub fn with_compression(mut self, compression: i32) -> Self {
        self.compression = compression;
        self
    }

    pub fn with_replay_window_bytes(mut self, replay_window_bytes: usize) -> Self {
        self.replay_window_bytes = replay_window_bytes;
        self
    }

    pub fn myself(&self) -> &str {
        &self.myself
    }

    pub const fn compression(&self) -> i32 {
        self.compression
    }

    pub const fn packet_type(&self) -> u8 {
        self.packet_type
    }

    pub const fn replay_window_bytes(&self) -> usize {
        self.replay_window_bytes
    }

    pub fn insert_peer_public_key(
        &mut self,
        peer: impl Into<String>,
        public_key: TincEd25519PublicKey,
    ) -> Option<TincEd25519PublicKey> {
        self.peer_keys.insert(peer.into(), public_key)
    }

    pub fn peer_public_key(&self, peer: &str) -> Option<TincEd25519PublicKey> {
        self.peer_keys.get(peer).copied()
    }

    pub fn pending_session(&self, peer: &str) -> Option<&SptpsHandshakeSession> {
        self.sessions.get(peer)
    }

    pub fn remove_pending_session(&mut self, peer: &str) -> bool {
        self.sessions.remove(peer).is_some()
    }

    pub fn restart_initiator(
        &mut self,
        peer: &str,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        self.remove_pending_session(peer);
        self.start_initiator(peer)
    }

    pub fn start_initiator(
        &mut self,
        peer: &str,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        if self.sessions.contains_key(peer) {
            return Ok(SptpsKeyExchangeResult::default());
        }

        let peer_key = self.peer_key(peer)?;
        let label = sptps_udp_label(&self.myself, peer);
        let mut session = SptpsHandshakeSession::start(
            true,
            self.private_key.clone(),
            peer_key,
            label,
            self.replay_window_bytes,
        )?;
        let outbound =
            drain_outbound_messages(&self.myself, peer, self.compression, &mut session, true);
        self.sessions.insert(peer.to_owned(), session);

        Ok(SptpsKeyExchangeResult {
            outbound,
            events: Vec::new(),
        })
    }

    pub fn receive_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        match message {
            MetaMessage::RequestKey(message) => self.receive_request_key(message),
            MetaMessage::AnswerKey(message) => self.receive_answer_key(message),
            message => Err(SptpsKeyExchangeError::UnsupportedMessage(message.request())),
        }
    }

    fn receive_request_key(
        &mut self,
        message: &RequestKeyMessage,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        let payload = message.decode_sptps_payload()?;
        self.ensure_destination(&payload)?;

        match payload.kind {
            SptpsKeyPayloadKind::InitialRequest => self.receive_initial_request(payload),
            SptpsKeyPayloadKind::TcpPacket => self.receive_existing_payload(payload),
            SptpsKeyPayloadKind::HandshakeAnswer => Err(SptpsKeyExchangeError::Protocol(
                SptpsKeyPayloadError::NotSptps,
            )),
        }
    }

    fn receive_answer_key(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        let payload = message.decode_sptps_payload()?;
        self.ensure_destination(&payload)?;
        self.receive_existing_payload(payload)
    }

    fn receive_initial_request(
        &mut self,
        payload: SptpsKeyPayload,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        let peer = payload.from;
        if let Some(session) = self.sessions.get(&peer)
            && session.initiator()
            && self.myself.as_str() < peer.as_str()
        {
            return Ok(SptpsKeyExchangeResult::default());
        }

        let peer_key = self.peer_key(&peer)?;
        let label = sptps_udp_label(&peer, &self.myself);
        let mut session = SptpsHandshakeSession::start(
            false,
            self.private_key.clone(),
            peer_key,
            label,
            self.replay_window_bytes,
        )?;
        let events = session.receive_datagram(&payload.data)?;
        let outbound =
            drain_outbound_messages(&self.myself, &peer, self.compression, &mut session, false);

        self.finish_or_store(peer, session, outbound, events)
    }

    fn receive_existing_payload(
        &mut self,
        payload: SptpsKeyPayload,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        let peer = payload.from;

        let (outbound, events) = {
            let session = self
                .sessions
                .get_mut(&peer)
                .ok_or_else(|| SptpsKeyExchangeError::MissingSession(peer.clone()))?;
            let events = session.receive_datagram(&payload.data)?;
            let outbound =
                drain_outbound_messages(&self.myself, &peer, self.compression, session, false);
            (outbound, events)
        };

        let session = self
            .sessions
            .remove(&peer)
            .ok_or_else(|| SptpsKeyExchangeError::MissingSession(peer.clone()))?;
        self.finish_or_store(peer, session, outbound, events)
    }

    fn finish_or_store(
        &mut self,
        peer: String,
        session: SptpsHandshakeSession,
        outbound: Vec<MetaMessage>,
        events: Vec<SptpsHandshakeEvent>,
    ) -> Result<SptpsKeyExchangeResult, SptpsKeyExchangeError> {
        let mut result = SptpsKeyExchangeResult {
            outbound,
            events: Vec::new(),
        };
        let mut established = false;

        for event in events {
            match event {
                SptpsHandshakeEvent::HandshakeComplete => established = true,
                SptpsHandshakeEvent::ApplicationRecord {
                    record_type,
                    payload,
                } => result
                    .events
                    .push(SptpsKeyExchangeEvent::ApplicationRecord {
                        peer: peer.clone(),
                        record_type,
                        payload,
                    }),
            }
        }

        if established {
            result.events.push(SptpsKeyExchangeEvent::Established {
                peer,
                session: Box::new(SptpsPeerSession::from_handshake_session(
                    session,
                    self.packet_type,
                )?),
            });
        } else {
            self.sessions.insert(peer, session);
        }

        Ok(result)
    }

    fn peer_key(&self, peer: &str) -> Result<TincEd25519PublicKey, SptpsKeyExchangeError> {
        self.peer_keys
            .get(peer)
            .copied()
            .ok_or_else(|| SptpsKeyExchangeError::UnknownPeerKey(peer.to_owned()))
    }

    fn ensure_destination(&self, payload: &SptpsKeyPayload) -> Result<(), SptpsKeyExchangeError> {
        if payload.to == self.myself {
            Ok(())
        } else {
            Err(SptpsKeyExchangeError::WrongDestination {
                expected: self.myself.clone(),
                actual: payload.to.clone(),
            })
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SptpsKeyExchangeResult {
    pub outbound: Vec<MetaMessage>,
    pub events: Vec<SptpsKeyExchangeEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SptpsKeyExchangeEvent {
    Established {
        peer: String,
        session: Box<SptpsPeerSession>,
    },
    ApplicationRecord {
        peer: String,
        record_type: u8,
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SptpsKeyExchangeError {
    UnknownPeerKey(String),
    MissingSession(String),
    WrongDestination { expected: String, actual: String },
    UnsupportedMessage(Request),
    Protocol(SptpsKeyPayloadError),
    Sptps(SptpsError),
}

impl fmt::Display for SptpsKeyExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPeerKey(peer) => write!(f, "missing Ed25519 public key for {peer}"),
            Self::MissingSession(peer) => write!(f, "missing pending SPTPS session for {peer}"),
            Self::WrongDestination { expected, actual } => write!(
                f,
                "SPTPS key exchange message is addressed to {actual}, expected {expected}"
            ),
            Self::UnsupportedMessage(request) => {
                write!(
                    f,
                    "unsupported SPTPS key exchange message {}",
                    request.name()
                )
            }
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Sptps(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SptpsKeyExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Sptps(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SptpsKeyPayloadError> for SptpsKeyExchangeError {
    fn from(error: SptpsKeyPayloadError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SptpsError> for SptpsKeyExchangeError {
    fn from(error: SptpsError) -> Self {
        Self::Sptps(error)
    }
}

pub fn sptps_udp_label(initiator: &str, responder: &str) -> Vec<u8> {
    let mut label = format!("tinc UDP key expansion {initiator} {responder}").into_bytes();
    label.push(0);
    label
}

fn drain_outbound_messages(
    myself: &str,
    peer: &str,
    compression: i32,
    session: &mut SptpsHandshakeSession,
    initial_request: bool,
) -> Vec<MetaMessage> {
    let mut outbound = Vec::new();
    let mut datagrams = session.drain_outbound().into_iter();

    if initial_request && let Some(datagram) = datagrams.next() {
        outbound.push(MetaMessage::RequestKey(
            RequestKeyMessage::sptps_initial_request(myself, peer, &datagram),
        ));
    }

    outbound.extend(datagrams.map(|datagram| {
        MetaMessage::AnswerKey(AnswerKeyMessage::sptps_handshake(
            myself,
            peer,
            &datagram,
            compression,
        ))
    }));

    outbound
}

#[cfg(test)]
mod tests {
    use tinc_core::graph::NodeId;
    use tinc_core::protocol::{AnswerKeyMessage, RequestKeyMessage};

    use crate::device::VpnPacket;
    use crate::sptps::{ED25519_SEED_LEN, TincEd25519PrivateKey};
    use crate::transport::{NodeIdTable, PacketCodec, SptpsPacketCodec};

    use super::*;

    fn key(byte: u8) -> TincEd25519PrivateKey {
        TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
    }

    fn exchange_pair() -> (SptpsKeyExchange, SptpsKeyExchange) {
        let alice_key = key(1);
        let bob_key = key(2);
        let mut alice = SptpsKeyExchange::new("alice", alice_key.clone(), 2).unwrap();
        let mut bob = SptpsKeyExchange::new("bob", bob_key.clone(), 2).unwrap();
        alice.insert_peer_public_key("bob", bob_key.public_key());
        bob.insert_peer_public_key("alice", alice_key.public_key());
        (alice, bob)
    }

    fn single_outbound(result: SptpsKeyExchangeResult) -> MetaMessage {
        assert!(result.events.is_empty());
        assert_eq!(1, result.outbound.len());
        result.outbound.into_iter().next().unwrap()
    }

    fn established_session(result: SptpsKeyExchangeResult, peer: &str) -> SptpsPeerSession {
        assert_eq!(1, result.events.len());
        assert!(result.outbound.is_empty());

        match result.events.into_iter().next().unwrap() {
            SptpsKeyExchangeEvent::Established {
                peer: actual,
                session,
            } => {
                assert_eq!(peer, actual);
                *session
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    fn ids() -> NodeIdTable {
        let mut ids = NodeIdTable::new();
        ids.insert("alice", NodeId::from_name("alice"));
        ids.insert("bob", NodeId::from_name("bob"));
        ids
    }

    #[test]
    fn sptps_udp_label_matches_tinc_null_terminated_label() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            b"tinc UDP key expansion alice bob\0".to_vec(),
            sptps_udp_label("alice", "bob")
        );
    }

    #[test]
    fn key_exchange_drives_initial_sptps_handshake_and_exports_peer_sessions() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, mut bob) = exchange_pair();

        let alice_kex = single_outbound(alice.start_initiator("bob").unwrap());
        assert!(matches!(alice_kex, MetaMessage::RequestKey(_)));
        assert!(alice.pending_session("bob").is_some());

        let bob_kex = single_outbound(bob.receive_meta_message(&alice_kex).unwrap());
        assert!(matches!(bob_kex, MetaMessage::AnswerKey(_)));
        assert!(bob.pending_session("alice").is_some());

        let alice_sig = single_outbound(alice.receive_meta_message(&bob_kex).unwrap());
        assert!(matches!(alice_sig, MetaMessage::AnswerKey(_)));

        let bob_result = bob.receive_meta_message(&alice_sig).unwrap();
        assert_eq!(1, bob_result.outbound.len());
        let bob_sig = bob_result.outbound[0].clone();
        let bob_session = match bob_result.events.into_iter().next().unwrap() {
            SptpsKeyExchangeEvent::Established { peer, session } => {
                assert_eq!("alice", peer);
                *session
            }
            event => panic!("unexpected event {event:?}"),
        };

        let alice_session =
            established_session(alice.receive_meta_message(&bob_sig).unwrap(), "bob");
        assert!(alice.pending_session("bob").is_none());
        assert!(bob.pending_session("alice").is_none());

        let mut alice_codec = SptpsPacketCodec::new(NodeId::from_name("alice"), ids());
        let mut bob_codec = SptpsPacketCodec::new(NodeId::from_name("bob"), ids());
        alice_codec.insert_peer("bob", alice_session);
        bob_codec.insert_peer("alice", bob_session);

        let packet = VpnPacket::new(b"vpn payload".to_vec()).unwrap();
        let datagram = alice_codec.encode("bob", &packet).unwrap();
        assert_eq!(packet, bob_codec.decode("alice", &datagram).unwrap());
    }

    #[test]
    fn responder_restarts_existing_pending_session_for_new_initial_request() {
        tinc_test_support::assert_can_create_netns();
        let alice_key = key(1);
        let bob_key = key(2);
        let mut alice = SptpsKeyExchange::new("alice", alice_key.clone(), 2).unwrap();
        let mut restarted_alice = SptpsKeyExchange::new("alice", alice_key, 2).unwrap();
        let mut bob = SptpsKeyExchange::new("bob", bob_key.clone(), 2).unwrap();
        alice.insert_peer_public_key("bob", bob_key.public_key());
        restarted_alice.insert_peer_public_key("bob", bob_key.public_key());
        bob.insert_peer_public_key("alice", key(1).public_key());

        let first = single_outbound(alice.start_initiator("bob").unwrap());
        bob.receive_meta_message(&first).unwrap();
        assert!(bob.pending_session("alice").is_some());

        let second = single_outbound(restarted_alice.start_initiator("bob").unwrap());
        let result = bob.receive_meta_message(&second).unwrap();

        assert_eq!(1, result.outbound.len());
        assert!(bob.pending_session("alice").is_some());
    }

    #[test]
    fn initiator_start_is_idempotent_while_session_is_pending() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, _) = exchange_pair();
        let first = alice.start_initiator("bob").unwrap();
        assert_eq!(1, first.outbound.len());
        assert!(alice.pending_session("bob").is_some());

        let second = alice.start_initiator("bob").unwrap();
        assert!(second.outbound.is_empty());
        assert!(second.events.is_empty());
        assert!(alice.pending_session("bob").unwrap().initiator());
    }

    #[test]
    fn simultaneous_initiators_converge_to_lower_name_initiator() {
        tinc_test_support::assert_can_create_netns();
        let (mut alice, mut bob) = exchange_pair();
        let alice_request = single_outbound(alice.start_initiator("bob").unwrap());
        let bob_request = single_outbound(bob.start_initiator("alice").unwrap());

        let ignored = alice.receive_meta_message(&bob_request).unwrap();
        assert!(ignored.outbound.is_empty());
        assert!(ignored.events.is_empty());
        assert!(alice.pending_session("bob").unwrap().initiator());

        let bob_answer = single_outbound(bob.receive_meta_message(&alice_request).unwrap());
        assert!(!bob.pending_session("alice").unwrap().initiator());

        let alice_sig = single_outbound(alice.receive_meta_message(&bob_answer).unwrap());
        let bob_result = bob.receive_meta_message(&alice_sig).unwrap();
        assert_eq!(1, bob_result.outbound.len());
        let bob_sig = bob_result.outbound[0].clone();
        let bob_session = match bob_result.events.into_iter().next().unwrap() {
            SptpsKeyExchangeEvent::Established { peer, session } => {
                assert_eq!("alice", peer);
                *session
            }
            event => panic!("unexpected event {event:?}"),
        };

        let alice_session =
            established_session(alice.receive_meta_message(&bob_sig).unwrap(), "bob");
        let mut alice_codec = SptpsPacketCodec::new(NodeId::from_name("alice"), ids());
        let mut bob_codec = SptpsPacketCodec::new(NodeId::from_name("bob"), ids());
        alice_codec.insert_peer("bob", alice_session);
        bob_codec.insert_peer("alice", bob_session);

        let packet = VpnPacket::new(b"simultaneous payload".to_vec()).unwrap();
        let datagram = alice_codec.encode("bob", &packet).unwrap();
        assert_eq!(packet, bob_codec.decode("alice", &datagram).unwrap());
    }

    #[test]
    fn key_exchange_rejects_missing_keys_wrong_destinations_and_missing_sessions() {
        tinc_test_support::assert_can_create_netns();
        let alice_key = key(3);
        let mut alice = SptpsKeyExchange::new("alice", alice_key, 2).unwrap();
        assert_eq!(
            Err(SptpsKeyExchangeError::UnknownPeerKey("bob".to_owned())),
            alice.start_initiator("bob")
        );

        let bob_key = key(4);
        alice.insert_peer_public_key("bob", bob_key.public_key());
        let wrong = MetaMessage::RequestKey(RequestKeyMessage::sptps_initial_request(
            "bob", "carol", b"abc",
        ));
        assert_eq!(
            Err(SptpsKeyExchangeError::WrongDestination {
                expected: "alice".to_owned(),
                actual: "carol".to_owned(),
            }),
            alice.receive_meta_message(&wrong)
        );

        let answer =
            MetaMessage::AnswerKey(AnswerKeyMessage::sptps_handshake("bob", "alice", b"abc", 0));
        assert_eq!(
            Err(SptpsKeyExchangeError::MissingSession("bob".to_owned())),
            alice.receive_meta_message(&answer)
        );

        let unsupported = MetaMessage::KeyChanged(tinc_core::protocol::KeyChangedMessage {
            nonce: 1,
            origin: "bob".to_owned(),
        });
        assert_eq!(
            Err(SptpsKeyExchangeError::UnsupportedMessage(
                Request::KeyChanged
            )),
            alice.receive_meta_message(&unsupported)
        );

        assert!(matches!(
            SptpsKeyExchange::new("alice", key(5), SPTPS_HANDSHAKE),
            Err(SptpsKeyExchangeError::Sptps(SptpsError::InvalidRecordType(
                SPTPS_HANDSHAKE
            )))
        ));
    }
}

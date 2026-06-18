// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tinc_core::graph::OPTION_PMTU_DISCOVERY;
use tinc_core::protocol::{
    AckMessage, ChallengeMessage, ChallengeReplyMessage, IdMessage, MetaKeyMessage, MetaMessage,
    MetaMessageError, PROT_MAJOR, Request, TcpPacketMessage, parse_meta_message,
};
use tinc_core::utils::{bin_to_hex, check_id, hex_to_bin, mem_eq};

use crate::meta::{
    MetaAuthEvent, MetaBodyKind, MetaConnectionEvent, MetaConnectionStep, MetaStreamDecoder,
    MetaStreamError, MetaStreamFrame,
};

pub const LEGACY_META_DIGEST_ALGO_SIZE: usize = usize::MAX;
pub const LEGACY_META_DEFAULT_DIGEST_NID: i32 = 672;
pub const LEGACY_META_DEFAULT_MAC_LENGTH: i32 = 4;
pub const LEGACY_META_COMPRESS_NONE: i32 = 0;
pub const LEGACY_META_PROTOCOL_MINOR: i32 = 0;
pub const LEGACY_META_UPGRADE_PROTOCOL_MINOR: i32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyMetaPrivateKey {
    Pem(RsaPrivateKey),
    Components {
        public_key: RsaPublicKey,
        private_exponent: BigUint,
    },
}

impl LegacyMetaPrivateKey {
    pub fn public_key(&self) -> RsaPublicKey {
        match self {
            Self::Pem(key) => RsaPublicKey::from(key),
            Self::Components { public_key, .. } => public_key.clone(),
        }
    }

    pub fn rsa_size(&self) -> usize {
        rsa_size(&self.public_key())
    }

    pub fn decrypt_block(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LegacyMetaError> {
        match self {
            Self::Pem(key) => legacy_meta_private_decrypt_pem(key, ciphertext),
            Self::Components {
                public_key,
                private_exponent,
            } => legacy_meta_private_decrypt_components(public_key, private_exponent, ciphertext),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMetaAuth {
    myself: String,
    peer: Option<String>,
    outgoing: bool,
    private_key: LegacyMetaPrivateKey,
    peer_public_key: RsaPublicKey,
    local_port: String,
    local_weight: i32,
    local_options: u32,
    local_protocol_minor: i32,
    negotiated_protocol_minor: i32,
    force_protocol_minor_zero: bool,
    local_upgrade_public_key: Option<String>,
    local_cipher_algorithm: LegacyMetaCipherAlgorithm,
    local_mac_length: i32,
    out_digest: LegacyMetaDigest,
    in_digest: Option<LegacyMetaDigest>,
    out_cipher: Option<LegacyMetaCipher>,
    in_cipher: Option<LegacyMetaCipher>,
    sent_challenge: Option<Vec<u8>>,
    received_challenge: Option<Vec<u8>>,
    state: LegacyMetaAuthState,
}

impl LegacyMetaAuth {
    pub fn new(
        myself: impl Into<String>,
        outgoing: bool,
        private_key: LegacyMetaPrivateKey,
        peer_public_key: RsaPublicKey,
        local_port: impl Into<String>,
        local_weight: i32,
        local_options: u32,
    ) -> Self {
        Self {
            myself: myself.into(),
            peer: None,
            outgoing,
            private_key,
            peer_public_key,
            local_port: local_port.into(),
            local_weight,
            local_options,
            local_protocol_minor: LEGACY_META_PROTOCOL_MINOR,
            negotiated_protocol_minor: LEGACY_META_PROTOCOL_MINOR,
            force_protocol_minor_zero: false,
            local_upgrade_public_key: None,
            local_cipher_algorithm: LegacyMetaCipherAlgorithm::Aes256Cfb,
            local_mac_length: LEGACY_META_DEFAULT_MAC_LENGTH,
            out_digest: LegacyMetaDigest::from_nid_and_length(
                LEGACY_META_DEFAULT_DIGEST_NID,
                LEGACY_META_DIGEST_ALGO_SIZE,
            )
            .expect("default legacy meta digest is supported"),
            in_digest: None,
            out_cipher: None,
            in_cipher: None,
            sent_challenge: None,
            received_challenge: None,
            state: LegacyMetaAuthState::ExpectId,
        }
    }

    pub fn with_cipher_algorithm(mut self, algorithm: LegacyMetaCipherAlgorithm) -> Self {
        self.local_cipher_algorithm = algorithm;
        self
    }

    pub fn with_mac_length(mut self, mac_length: i32) -> Self {
        self.local_mac_length = mac_length;
        self
    }

    pub fn with_protocol_minor(mut self, minor: i32) -> Self {
        self.local_protocol_minor = minor;
        self
    }

    pub fn with_forced_protocol_minor_zero(mut self, force: bool) -> Self {
        self.force_protocol_minor_zero = force;
        if force {
            self.local_protocol_minor = LEGACY_META_PROTOCOL_MINOR;
        }
        self
    }

    pub fn with_upgrade_public_key(mut self, public_key: impl Into<String>) -> Self {
        self.local_upgrade_public_key = Some(public_key.into());
        self
    }

    pub const fn state(&self) -> LegacyMetaAuthState {
        self.state
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    pub fn outgoing(&self) -> bool {
        self.outgoing
    }

    pub fn inbound_encrypted(&self) -> bool {
        self.in_cipher.is_some()
    }

    pub fn outbound_encrypted(&self) -> bool {
        self.out_cipher.is_some()
    }

    pub fn local_id_message(&self) -> MetaMessage {
        MetaMessage::Id(IdMessage {
            name: self.myself.clone(),
            protocol_major: PROT_MAJOR as i32,
            protocol_minor: Some(self.local_protocol_minor),
        })
    }

    pub fn receive_meta_message_with_random<F>(
        &mut self,
        message: &MetaMessage,
        fill_random: F,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError>
    where
        F: FnMut(&mut [u8]),
    {
        match message {
            MetaMessage::Id(message) => self.receive_id(message, fill_random),
            MetaMessage::MetaKey(message) => self.receive_metakey(message, fill_random),
            MetaMessage::Challenge(message) => self.receive_challenge(message),
            MetaMessage::ChallengeReply(message) => self.receive_challenge_reply(message),
            MetaMessage::Ack(message) => self.receive_ack(message),
            MetaMessage::TerminateRequest => self.receive_terminate_request(),
            message => Err(LegacyMetaAuthError::UnexpectedMessage {
                expected: self.state.expected_request(),
                actual: message.request(),
            }),
        }
    }

    pub fn encode_outbound_message(
        &mut self,
        message: &LegacyMetaOutboundMessage,
    ) -> Result<Vec<u8>, LegacyMetaAuthError> {
        let line = legacy_meta_encode_line(&message.message);
        if message.encrypted {
            self.encrypt_outbound(&line)
        } else {
            Ok(line)
        }
    }

    pub fn encrypt_outbound(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, LegacyMetaAuthError> {
        self.out_cipher
            .as_mut()
            .ok_or(LegacyMetaAuthError::MissingOutCipher)?
            .apply_encrypt(plaintext)
            .map_err(Into::into)
    }

    pub fn decrypt_inbound(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, LegacyMetaAuthError> {
        self.in_cipher
            .as_mut()
            .ok_or(LegacyMetaAuthError::MissingInCipher)?
            .apply_decrypt(ciphertext)
            .map_err(Into::into)
    }

    fn receive_id<F>(
        &mut self,
        message: &IdMessage,
        fill_random: F,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError>
    where
        F: FnMut(&mut [u8]),
    {
        self.ensure_expected(Request::Id)?;
        validate_legacy_peer_id(&self.myself, message)?;

        if message.protocol_major != PROT_MAJOR as i32 {
            return Err(LegacyMetaAuthError::IncompatibleProtocol {
                expected: PROT_MAJOR as i32,
                actual: message.protocol_major,
            });
        }

        let remote_minor = if self.force_protocol_minor_zero {
            LEGACY_META_PROTOCOL_MINOR
        } else {
            message.protocol_minor.unwrap_or(0)
        };
        self.negotiated_protocol_minor = if remote_minor == LEGACY_META_PROTOCOL_MINOR {
            LEGACY_META_PROTOCOL_MINOR
        } else if self.local_upgrade_public_key.is_some() {
            LEGACY_META_UPGRADE_PROTOCOL_MINOR
        } else {
            return Err(LegacyMetaAuthError::UnsupportedProtocolMinor(remote_minor));
        };

        self.peer = Some(message.name.clone());
        let mut step = LegacyMetaAuthStep::default();
        if !self.outgoing {
            step.outbound.push(LegacyMetaOutboundMessage::plaintext(
                self.local_id_message(),
            ));
        }
        step.outbound.push(self.send_metakey(fill_random)?);
        self.state = LegacyMetaAuthState::ExpectMetaKey;
        Ok(step)
    }

    fn receive_metakey<F>(
        &mut self,
        message: &MetaKeyMessage,
        fill_random: F,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError>
    where
        F: FnMut(&mut [u8]),
    {
        self.ensure_expected(Request::MetaKey)?;

        if message.cipher == 0 {
            return Err(LegacyMetaAuthError::Crypto(
                LegacyMetaError::UnsupportedCipher(message.cipher),
            ));
        }
        if message.digest == 0 {
            return Err(LegacyMetaAuthError::Crypto(
                LegacyMetaError::UnsupportedDigest(message.digest),
            ));
        }

        let algorithm = LegacyMetaCipherAlgorithm::from_nid(message.cipher)
            .ok_or(LegacyMetaError::UnsupportedCipher(message.cipher))?;
        let digest =
            LegacyMetaDigest::from_nid_and_length(message.digest, LEGACY_META_DIGEST_ALGO_SIZE)
                .ok_or(LegacyMetaError::UnsupportedDigest(message.digest))?;
        let len = self.private_key.rsa_size();
        let encrypted_key = hex_to_bin(&message.key, len);
        if encrypted_key.len() != len {
            return Err(LegacyMetaError::InvalidRsaBlockLength {
                expected: len,
                actual: encrypted_key.len(),
            }
            .into());
        }
        let key = self.private_key.decrypt_block(&encrypted_key)?;
        self.in_cipher = Some(LegacyMetaCipher::from_rsa_key_material(algorithm, &key)?);
        self.in_digest = Some(digest);

        let mut step = LegacyMetaAuthStep::default();
        step.outbound.push(self.send_challenge(fill_random));
        self.state = LegacyMetaAuthState::ExpectChallenge;
        Ok(step)
    }

    fn receive_challenge(
        &mut self,
        message: &ChallengeMessage,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError> {
        self.ensure_expected(Request::Challenge)?;

        let len = self.private_key.rsa_size();
        if message.data.len() != len * 2 {
            return Err(LegacyMetaAuthError::InvalidChallengeLength {
                expected: len * 2,
                actual: message.data.len(),
            });
        }
        let challenge = hex_to_bin(&message.data, len);
        if challenge.len() != len {
            return Err(LegacyMetaAuthError::InvalidChallengeLength {
                expected: len * 2,
                actual: message.data.len(),
            });
        }
        self.received_challenge = Some(challenge);

        let mut step = LegacyMetaAuthStep::default();
        if self.outgoing {
            step.outbound.push(self.send_challenge_reply()?);
        }
        self.state = LegacyMetaAuthState::ExpectChallengeReply;
        Ok(step)
    }

    fn receive_challenge_reply(
        &mut self,
        message: &ChallengeReplyMessage,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError> {
        self.ensure_expected(Request::ChallengeReply)?;

        let challenge = self
            .sent_challenge
            .take()
            .ok_or(LegacyMetaAuthError::MissingSentChallenge)?;
        self.out_digest
            .verify_hex(&challenge, &message.digest)
            .map_err(LegacyMetaAuthError::Crypto)?;

        let mut step = LegacyMetaAuthStep::default();
        if !self.outgoing {
            step.outbound.push(self.send_challenge_reply()?);
        }
        step.outbound
            .push(LegacyMetaOutboundMessage::encrypted(self.ack_message()?));
        self.state = LegacyMetaAuthState::ExpectAck;
        Ok(step)
    }

    fn receive_ack(
        &mut self,
        message: &AckMessage,
    ) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError> {
        self.ensure_expected(Request::Ack)?;

        if self.negotiated_protocol_minor == LEGACY_META_UPGRADE_PROTOCOL_MINOR {
            let AckMessage::Payload(public_key) = message else {
                return Err(LegacyMetaAuthError::UnexpectedAckShape);
            };

            let peer = self.peer.clone().ok_or(LegacyMetaAuthError::MissingPeer)?;
            self.state = LegacyMetaAuthState::UpgradeTerminating;
            return Ok(LegacyMetaAuthStep {
                outbound: vec![LegacyMetaOutboundMessage::encrypted(
                    MetaMessage::TerminateRequest,
                )],
                events: vec![LegacyMetaAuthEvent::LegacyEd25519Upgrade {
                    peer,
                    public_key: public_key.clone(),
                }],
            });
        }

        let AckMessage::Connection {
            port,
            weight,
            options,
        } = message
        else {
            return Err(LegacyMetaAuthError::UnexpectedAckShape);
        };

        let peer = self.peer.clone().ok_or(LegacyMetaAuthError::MissingPeer)?;
        self.state = LegacyMetaAuthState::Activated;
        Ok(LegacyMetaAuthStep {
            outbound: Vec::new(),
            events: vec![LegacyMetaAuthEvent::Activated {
                peer,
                port: port.clone(),
                weight: negotiated_weight(self.local_weight, *weight),
                options: negotiated_connection_options(self.local_options, *options),
            }],
        })
    }

    fn receive_terminate_request(&mut self) -> Result<LegacyMetaAuthStep, LegacyMetaAuthError> {
        if self.state == LegacyMetaAuthState::UpgradeTerminating {
            Ok(LegacyMetaAuthStep::default())
        } else {
            Err(LegacyMetaAuthError::UnexpectedMessage {
                expected: self.state.expected_request(),
                actual: Request::TerminateRequest,
            })
        }
    }

    fn send_metakey<F>(
        &mut self,
        fill_random: F,
    ) -> Result<LegacyMetaOutboundMessage, LegacyMetaAuthError>
    where
        F: FnMut(&mut [u8]),
    {
        let len = rsa_size(&self.peer_public_key);
        let key = legacy_meta_generate_rsa_key_material(len, fill_random)?;
        self.out_cipher = Some(LegacyMetaCipher::from_rsa_key_material(
            self.local_cipher_algorithm,
            &key,
        )?);
        let encrypted_key = legacy_meta_public_encrypt(&self.peer_public_key, &key)?;

        Ok(LegacyMetaOutboundMessage::plaintext(MetaMessage::MetaKey(
            MetaKeyMessage {
                cipher: self.local_cipher_algorithm.nid(),
                digest: self.out_digest.nid(),
                mac_length: self.local_mac_length,
                compression: LEGACY_META_COMPRESS_NONE,
                key: bin_to_hex(&encrypted_key),
            },
        )))
    }

    fn send_challenge<F>(&mut self, mut fill_random: F) -> LegacyMetaOutboundMessage
    where
        F: FnMut(&mut [u8]),
    {
        let len = rsa_size(&self.peer_public_key);
        let mut challenge = vec![0; len];
        fill_random(&mut challenge);
        self.sent_challenge = Some(challenge.clone());

        LegacyMetaOutboundMessage::encrypted(MetaMessage::Challenge(ChallengeMessage {
            data: bin_to_hex(&challenge),
        }))
    }

    fn send_challenge_reply(&mut self) -> Result<LegacyMetaOutboundMessage, LegacyMetaAuthError> {
        let challenge = self
            .received_challenge
            .take()
            .ok_or(LegacyMetaAuthError::MissingReceivedChallenge)?;
        let digest = self.in_digest.ok_or(LegacyMetaAuthError::MissingInDigest)?;

        Ok(LegacyMetaOutboundMessage::encrypted(
            MetaMessage::ChallengeReply(ChallengeReplyMessage {
                digest: digest.create_hex(&challenge),
            }),
        ))
    }

    fn ack_message(&self) -> Result<MetaMessage, LegacyMetaAuthError> {
        if self.negotiated_protocol_minor == LEGACY_META_UPGRADE_PROTOCOL_MINOR {
            let public_key = self
                .local_upgrade_public_key
                .clone()
                .ok_or(LegacyMetaAuthError::MissingUpgradePublicKey)?;
            return Ok(MetaMessage::Ack(AckMessage::Payload(public_key)));
        }

        Ok(MetaMessage::Ack(AckMessage::Connection {
            port: self.local_port.clone(),
            weight: self.local_weight,
            options: self.local_options,
        }))
    }

    fn ensure_expected(&self, actual: Request) -> Result<(), LegacyMetaAuthError> {
        let expected = self.state.expected_request();
        if expected == Some(actual) {
            Ok(())
        } else {
            Err(LegacyMetaAuthError::UnexpectedMessage { expected, actual })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMetaAuthState {
    ExpectId,
    ExpectMetaKey,
    ExpectChallenge,
    ExpectChallengeReply,
    ExpectAck,
    UpgradeTerminating,
    Activated,
}

impl LegacyMetaAuthState {
    pub const fn expected_request(self) -> Option<Request> {
        match self {
            Self::ExpectId => Some(Request::Id),
            Self::ExpectMetaKey => Some(Request::MetaKey),
            Self::ExpectChallenge => Some(Request::Challenge),
            Self::ExpectChallengeReply => Some(Request::ChallengeReply),
            Self::ExpectAck => Some(Request::Ack),
            Self::UpgradeTerminating => Some(Request::TerminateRequest),
            Self::Activated => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyMetaAuthStep {
    pub outbound: Vec<LegacyMetaOutboundMessage>,
    pub events: Vec<LegacyMetaAuthEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMetaOutboundMessage {
    pub message: MetaMessage,
    pub encrypted: bool,
}

impl LegacyMetaOutboundMessage {
    pub fn plaintext(message: MetaMessage) -> Self {
        Self {
            message,
            encrypted: false,
        }
    }

    pub fn encrypted(message: MetaMessage) -> Self {
        Self {
            message,
            encrypted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyMetaAuthEvent {
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMetaConnectionDriver {
    auth: LegacyMetaAuth,
    raw_buffer: Vec<u8>,
    decoder: MetaStreamDecoder,
}

impl LegacyMetaConnectionDriver {
    pub fn new(auth: LegacyMetaAuth) -> Self {
        Self {
            auth,
            raw_buffer: Vec::new(),
            decoder: MetaStreamDecoder::new(),
        }
    }

    pub fn auth(&self) -> &LegacyMetaAuth {
        &self.auth
    }

    pub fn auth_mut(&mut self) -> &mut LegacyMetaAuth {
        &mut self.auth
    }

    pub fn initial_id_bytes(&self) -> Vec<u8> {
        legacy_meta_encode_line(&self.auth.local_id_message())
    }

    pub fn receive_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<MetaConnectionStep, LegacyMetaConnectionError> {
        self.raw_buffer.extend_from_slice(data);
        let mut step = MetaConnectionStep::default();

        loop {
            if self.auth.inbound_encrypted() {
                if self.raw_buffer.is_empty() {
                    break;
                }
                let plaintext = self.auth.decrypt_inbound(&self.raw_buffer)?;
                self.raw_buffer.clear();
                self.decoder.push(&plaintext);

                loop {
                    let Some(frame) = self.decoder.next_plaintext_frame()? else {
                        break;
                    };
                    self.handle_frame(frame, &mut step)?;
                }
            } else {
                let Some(newline) = self.raw_buffer.iter().position(|byte| *byte == b'\n') else {
                    break;
                };
                let line = self.raw_buffer.drain(..=newline).collect::<Vec<_>>();
                let line = legacy_meta_decode_line(line)?;
                self.handle_meta_line(&line, &mut step)?;
            }
        }

        Ok(step)
    }

    pub fn send_meta_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<Vec<u8>, LegacyMetaConnectionError> {
        if message.request() == Request::Id {
            return Ok(legacy_meta_encode_line(message));
        }
        self.auth
            .encrypt_outbound(&legacy_meta_encode_line(message))
            .map_err(Into::into)
    }

    pub fn send_tcp_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<Vec<u8>>, LegacyMetaConnectionError> {
        self.ensure_activated()?;
        let length = checked_tcp_packet_length(packet.len())?;
        let header = MetaMessage::TcpPacket(TcpPacketMessage { length });
        Ok(vec![
            self.send_meta_message(&header)?,
            self.auth.encrypt_outbound(packet)?,
        ])
    }

    pub fn send_sptps_packet(
        &mut self,
        _packet: &[u8],
    ) -> Result<Vec<Vec<u8>>, LegacyMetaConnectionError> {
        Err(LegacyMetaConnectionError::UnsupportedSptpsTcpPacket)
    }

    fn ensure_activated(&self) -> Result<(), LegacyMetaConnectionError> {
        if self.auth.state() == LegacyMetaAuthState::Activated {
            Ok(())
        } else {
            Err(LegacyMetaConnectionError::NotActivated(self.auth.state()))
        }
    }

    fn handle_frame(
        &mut self,
        frame: MetaStreamFrame,
        step: &mut MetaConnectionStep,
    ) -> Result<(), LegacyMetaConnectionError> {
        match frame {
            MetaStreamFrame::Line(line) => self.handle_meta_line(&line, step),
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
            MetaStreamFrame::SptpsRecord(_) => {
                Err(LegacyMetaConnectionError::UnexpectedSptpsRecord)
            }
        }
    }

    fn handle_meta_line(
        &mut self,
        line: &str,
        step: &mut MetaConnectionStep,
    ) -> Result<(), LegacyMetaConnectionError> {
        let message = parse_meta_message(line)?;
        step.events
            .push(MetaConnectionEvent::Message(message.clone()));

        if self.auth.state() != LegacyMetaAuthState::Activated {
            let auth_step = self
                .auth
                .receive_meta_message_with_random(&message, fill_legacy_meta_random)?;
            return self.apply_auth_step(auth_step, step);
        }

        self.decoder.observe_meta_message(&message);
        Ok(())
    }

    fn apply_auth_step(
        &mut self,
        auth_step: LegacyMetaAuthStep,
        step: &mut MetaConnectionStep,
    ) -> Result<(), LegacyMetaConnectionError> {
        for message in auth_step.outbound {
            step.outbound
                .push(self.auth.encode_outbound_message(&message)?);
        }

        for event in auth_step.events {
            match event {
                LegacyMetaAuthEvent::Activated {
                    peer,
                    port,
                    weight,
                    options,
                } => step
                    .events
                    .push(MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                        peer,
                        port,
                        weight,
                        options,
                    })),
                LegacyMetaAuthEvent::LegacyEd25519Upgrade { peer, public_key } => {
                    step.events.push(MetaConnectionEvent::Auth(
                        MetaAuthEvent::LegacyEd25519Upgrade { peer, public_key },
                    ))
                }
            }
        }

        Ok(())
    }
}

fn fill_legacy_meta_random(bytes: &mut [u8]) {
    getrandom::getrandom(bytes).expect("legacy meta random generation failed");
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyMetaConnectionError {
    Stream(MetaStreamError),
    Parse(MetaMessageError),
    Auth(LegacyMetaAuthError),
    NotActivated(LegacyMetaAuthState),
    PacketTooLarge { maximum: usize, actual: usize },
    UnsupportedSptpsTcpPacket,
    UnexpectedSptpsRecord,
}

impl fmt::Display for LegacyMetaConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::Auth(error) => write!(f, "{error}"),
            Self::NotActivated(state) => {
                write!(
                    f,
                    "legacy meta connection is not activated, current state is {state:?}"
                )
            }
            Self::PacketTooLarge { maximum, actual } => {
                write!(
                    f,
                    "TCP packet is too large: {actual} bytes, maximum is {maximum}"
                )
            }
            Self::UnsupportedSptpsTcpPacket => {
                write!(f, "legacy meta connection cannot carry SPTPS TCP packets")
            }
            Self::UnexpectedSptpsRecord => {
                write!(f, "legacy meta connection received an SPTPS TCP record")
            }
        }
    }
}

impl std::error::Error for LegacyMetaConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Auth(error) => Some(error),
            Self::NotActivated(_)
            | Self::PacketTooLarge { .. }
            | Self::UnsupportedSptpsTcpPacket
            | Self::UnexpectedSptpsRecord => None,
        }
    }
}

impl From<MetaStreamError> for LegacyMetaConnectionError {
    fn from(error: MetaStreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<MetaMessageError> for LegacyMetaConnectionError {
    fn from(error: MetaMessageError) -> Self {
        Self::Parse(error)
    }
}

impl From<LegacyMetaAuthError> for LegacyMetaConnectionError {
    fn from(error: LegacyMetaAuthError) -> Self {
        Self::Auth(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyMetaAuthError {
    InvalidPeerName(String),
    SelfConnection(String),
    IncompatibleProtocol {
        expected: i32,
        actual: i32,
    },
    UnsupportedProtocolMinor(i32),
    UnexpectedMessage {
        expected: Option<Request>,
        actual: Request,
    },
    UnexpectedAckShape,
    MissingPeer,
    MissingOutCipher,
    MissingInCipher,
    MissingInDigest,
    MissingSentChallenge,
    MissingReceivedChallenge,
    MissingUpgradePublicKey,
    InvalidChallengeLength {
        expected: usize,
        actual: usize,
    },
    Crypto(LegacyMetaError),
}

impl fmt::Display for LegacyMetaAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerName(name) => write!(f, "invalid legacy meta peer name {name}"),
            Self::SelfConnection(name) => write!(f, "legacy meta peer name {name} is myself"),
            Self::IncompatibleProtocol { expected, actual } => {
                write!(
                    f,
                    "incompatible legacy meta protocol major {actual}, expected {expected}"
                )
            }
            Self::UnsupportedProtocolMinor(minor) => {
                write!(
                    f,
                    "protocol minor {minor} requires a non-legacy meta auth path"
                )
            }
            Self::UnexpectedMessage { expected, actual } => write!(
                f,
                "unexpected legacy meta auth message {}, expected {}",
                actual.name(),
                expected.map(Request::name).unwrap_or("no more messages")
            ),
            Self::UnexpectedAckShape => write!(f, "unexpected ACK shape for legacy meta auth"),
            Self::MissingPeer => write!(f, "missing legacy meta auth peer"),
            Self::MissingOutCipher => write!(f, "missing legacy meta outbound cipher"),
            Self::MissingInCipher => write!(f, "missing legacy meta inbound cipher"),
            Self::MissingInDigest => write!(f, "missing legacy meta inbound digest"),
            Self::MissingSentChallenge => write!(f, "missing legacy meta sent challenge"),
            Self::MissingReceivedChallenge => write!(f, "missing legacy meta received challenge"),
            Self::MissingUpgradePublicKey => {
                write!(
                    f,
                    "missing local Ed25519 public key for legacy meta upgrade"
                )
            }
            Self::InvalidChallengeLength { expected, actual } => write!(
                f,
                "legacy meta challenge has wrong hex length: expected {expected}, got {actual}"
            ),
            Self::Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LegacyMetaAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LegacyMetaError> for LegacyMetaAuthError {
    fn from(error: LegacyMetaError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMetaCipherAlgorithm {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
}

impl LegacyMetaCipherAlgorithm {
    pub const fn from_nid(nid: i32) -> Option<Self> {
        match nid {
            421 => Some(Self::Aes128Cfb),
            425 => Some(Self::Aes192Cfb),
            429 => Some(Self::Aes256Cfb),
            _ => None,
        }
    }

    pub const fn for_plain_key_len(key_len: usize) -> Self {
        if key_len <= 16 {
            Self::Aes128Cfb
        } else if key_len <= 24 {
            Self::Aes192Cfb
        } else {
            Self::Aes256Cfb
        }
    }

    pub const fn nid(self) -> i32 {
        match self {
            Self::Aes128Cfb => 421,
            Self::Aes192Cfb => 425,
            Self::Aes256Cfb => 429,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb => 16,
            Self::Aes192Cfb => 24,
            Self::Aes256Cfb => 32,
        }
    }

    pub const fn iv_len(self) -> usize {
        16
    }

    pub const fn key_material_len(self) -> usize {
        self.key_len() + self.iv_len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMetaCipher {
    algorithm: LegacyMetaCipherAlgorithm,
    key: Vec<u8>,
    feedback: [u8; 16],
    stream: [u8; 16],
    position: usize,
}

impl LegacyMetaCipher {
    pub fn from_rsa_key_material(
        algorithm: LegacyMetaCipherAlgorithm,
        rsa_key_material: &[u8],
    ) -> Result<Self, LegacyMetaError> {
        let (key, iv) = legacy_meta_key_iv_from_rsa(algorithm, rsa_key_material)?;
        let feedback: [u8; 16] = iv
            .try_into()
            .expect("legacy meta AES CFB IV length is fixed at 16");
        Ok(Self {
            algorithm,
            key: key.to_vec(),
            feedback,
            stream: [0; 16],
            position: 0,
        })
    }

    pub const fn algorithm(&self) -> LegacyMetaCipherAlgorithm {
        self.algorithm
    }

    pub fn apply_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, LegacyMetaError> {
        legacy_meta_aes_cfb_apply(
            self.algorithm,
            &self.key,
            &mut self.feedback,
            &mut self.stream,
            &mut self.position,
            plaintext,
            true,
        )
    }

    pub fn apply_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, LegacyMetaError> {
        legacy_meta_aes_cfb_apply(
            self.algorithm,
            &self.key,
            &mut self.feedback,
            &mut self.stream,
            &mut self.position,
            ciphertext,
            false,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMetaDigest {
    Sha1 { length: usize },
    Sha256 { length: usize },
    Sha384 { length: usize },
    Sha512 { length: usize },
}

impl LegacyMetaDigest {
    pub fn from_nid_and_length(nid: i32, length: usize) -> Option<Self> {
        let maximum = match nid {
            64 => 20,
            672 => 32,
            673 => 48,
            674 => 64,
            _ => return None,
        };
        let length = if length == LEGACY_META_DIGEST_ALGO_SIZE || length > maximum {
            maximum
        } else {
            length
        };

        match nid {
            64 => Some(Self::Sha1 { length }),
            672 => Some(Self::Sha256 { length }),
            673 => Some(Self::Sha384 { length }),
            674 => Some(Self::Sha512 { length }),
            _ => None,
        }
    }

    pub const fn nid(self) -> i32 {
        match self {
            Self::Sha1 { .. } => 64,
            Self::Sha256 { .. } => 672,
            Self::Sha384 { .. } => 673,
            Self::Sha512 { .. } => 674,
        }
    }

    pub const fn length(self) -> usize {
        match self {
            Self::Sha1 { length }
            | Self::Sha256 { length }
            | Self::Sha384 { length }
            | Self::Sha512 { length } => length,
        }
    }

    pub fn create(self, input: &[u8]) -> Vec<u8> {
        let mut digest = match self {
            Self::Sha1 { .. } => Sha1::digest(input).to_vec(),
            Self::Sha256 { .. } => Sha256::digest(input).to_vec(),
            Self::Sha384 { .. } => Sha384::digest(input).to_vec(),
            Self::Sha512 { .. } => Sha512::digest(input).to_vec(),
        };
        digest.truncate(self.length());
        digest
    }

    pub fn create_hex(self, input: &[u8]) -> String {
        bin_to_hex(&self.create(input))
    }

    pub fn verify_hex(self, input: &[u8], expected_hex: &str) -> Result<(), LegacyMetaError> {
        let expected = hex_to_bin(expected_hex, self.length());
        if expected.len() != self.length() {
            return Err(LegacyMetaError::InvalidDigestLength {
                expected: self.length(),
                actual: expected.len(),
            });
        }
        let actual = self.create(input);
        if mem_eq(&actual, &expected) {
            Ok(())
        } else {
            Err(LegacyMetaError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyMetaError {
    UnsupportedCipher(i32),
    UnsupportedDigest(i32),
    InvalidKeyMaterialLength { expected: usize, actual: usize },
    InvalidRsaBlockLength { expected: usize, actual: usize },
    RsaValueTooLarge,
    InvalidDigestLength { expected: usize, actual: usize },
    DigestMismatch,
}

impl fmt::Display for LegacyMetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCipher(nid) => write!(f, "unsupported legacy meta cipher NID {nid}"),
            Self::UnsupportedDigest(nid) => write!(f, "unsupported legacy meta digest NID {nid}"),
            Self::InvalidKeyMaterialLength { expected, actual } => write!(
                f,
                "legacy meta key material has wrong length: expected at least {expected}, got {actual}"
            ),
            Self::InvalidRsaBlockLength { expected, actual } => write!(
                f,
                "legacy meta RSA block has wrong length: expected {expected}, got {actual}"
            ),
            Self::RsaValueTooLarge => write!(f, "legacy meta RSA value is larger than the modulus"),
            Self::InvalidDigestLength { expected, actual } => write!(
                f,
                "legacy meta digest has wrong length: expected {expected}, got {actual}"
            ),
            Self::DigestMismatch => write!(f, "legacy meta challenge digest mismatch"),
        }
    }
}

impl std::error::Error for LegacyMetaError {}

pub fn legacy_meta_generate_rsa_key_material<F>(
    rsa_size: usize,
    mut fill_random: F,
) -> Result<Vec<u8>, LegacyMetaError>
where
    F: FnMut(&mut [u8]),
{
    let mut key = vec![0; rsa_size];
    fill_random(&mut key);
    if let Some(first) = key.first_mut() {
        *first &= 0x7f;
    }
    Ok(key)
}

pub fn legacy_meta_public_encrypt(
    public_key: &RsaPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, LegacyMetaError> {
    let size = rsa_size(public_key);
    if plaintext.len() != size {
        return Err(LegacyMetaError::InvalidRsaBlockLength {
            expected: size,
            actual: plaintext.len(),
        });
    }
    let message = BigUint::from_bytes_be(plaintext);
    if &message >= public_key.n() {
        return Err(LegacyMetaError::RsaValueTooLarge);
    }
    Ok(biguint_to_fixed_len(
        message.modpow(public_key.e(), public_key.n()),
        size,
    ))
}

pub fn legacy_meta_private_decrypt_pem(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, LegacyMetaError> {
    let size = rsa_size(private_key);
    if ciphertext.len() != size {
        return Err(LegacyMetaError::InvalidRsaBlockLength {
            expected: size,
            actual: ciphertext.len(),
        });
    }
    Ok(biguint_to_fixed_len(
        BigUint::from_bytes_be(ciphertext).modpow(private_key.d(), private_key.n()),
        size,
    ))
}

pub fn legacy_meta_private_decrypt_components(
    public_key: &RsaPublicKey,
    private_exponent: &BigUint,
    ciphertext: &[u8],
) -> Result<Vec<u8>, LegacyMetaError> {
    let size = rsa_size(public_key);
    if ciphertext.len() != size {
        return Err(LegacyMetaError::InvalidRsaBlockLength {
            expected: size,
            actual: ciphertext.len(),
        });
    }
    Ok(biguint_to_fixed_len(
        BigUint::from_bytes_be(ciphertext).modpow(private_exponent, public_key.n()),
        size,
    ))
}

pub fn legacy_meta_key_iv_from_rsa(
    algorithm: LegacyMetaCipherAlgorithm,
    rsa_key_material: &[u8],
) -> Result<(&[u8], &[u8]), LegacyMetaError> {
    let expected = algorithm.key_material_len();
    if rsa_key_material.len() < expected {
        return Err(LegacyMetaError::InvalidKeyMaterialLength {
            expected,
            actual: rsa_key_material.len(),
        });
    }

    let key_start = rsa_key_material.len() - algorithm.key_len();
    let iv_start = key_start - algorithm.iv_len();
    Ok((
        &rsa_key_material[key_start..],
        &rsa_key_material[iv_start..key_start],
    ))
}

pub fn rsa_size(key: &impl PublicKeyParts) -> usize {
    key.n().bits().div_ceil(8)
}

pub fn legacy_meta_encode_line(message: &MetaMessage) -> Vec<u8> {
    let mut line = message.to_string().into_bytes();
    line.push(b'\n');
    line
}

fn legacy_meta_decode_line(mut line: Vec<u8>) -> Result<String, MetaStreamError> {
    if line.last() == Some(&b'\n') {
        line.pop();
    }

    if line.last() == Some(&b'\r') {
        line.pop();
    }

    String::from_utf8(line).map_err(|_| MetaStreamError::InvalidUtf8)
}

fn checked_tcp_packet_length(length: usize) -> Result<u16, LegacyMetaConnectionError> {
    let maximum = i16::MAX as usize;

    if length > maximum {
        return Err(LegacyMetaConnectionError::PacketTooLarge {
            maximum,
            actual: length,
        });
    }

    Ok(length as u16)
}

fn validate_legacy_peer_id(myself: &str, message: &IdMessage) -> Result<(), LegacyMetaAuthError> {
    if !check_id(&message.name) {
        return Err(LegacyMetaAuthError::InvalidPeerName(message.name.clone()));
    }

    if message.name == myself {
        return Err(LegacyMetaAuthError::SelfConnection(message.name.clone()));
    }

    Ok(())
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

fn legacy_meta_aes_cfb_apply(
    algorithm: LegacyMetaCipherAlgorithm,
    key: &[u8],
    feedback: &mut [u8; 16],
    stream: &mut [u8; 16],
    position: &mut usize,
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, LegacyMetaError> {
    if key.len() != algorithm.key_len() {
        return Err(LegacyMetaError::InvalidKeyMaterialLength {
            expected: algorithm.key_len(),
            actual: key.len(),
        });
    }

    match algorithm {
        LegacyMetaCipherAlgorithm::Aes128Cfb => {
            let cipher = Aes128::new_from_slice(key).expect("key length checked");
            Ok(cfb128_apply(
                cipher, feedback, stream, position, input, encrypt,
            ))
        }
        LegacyMetaCipherAlgorithm::Aes192Cfb => {
            let cipher = Aes192::new_from_slice(key).expect("key length checked");
            Ok(cfb128_apply(
                cipher, feedback, stream, position, input, encrypt,
            ))
        }
        LegacyMetaCipherAlgorithm::Aes256Cfb => {
            let cipher = Aes256::new_from_slice(key).expect("key length checked");
            Ok(cfb128_apply(
                cipher, feedback, stream, position, input, encrypt,
            ))
        }
    }
}

fn cfb128_apply<C: BlockEncrypt>(
    cipher: C,
    feedback: &mut [u8; 16],
    stream: &mut [u8; 16],
    position: &mut usize,
    input: &[u8],
    encrypt: bool,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for byte in input {
        if *position == 0 {
            let mut block = GenericArray::clone_from_slice(feedback);
            cipher.encrypt_block(&mut block);
            stream.copy_from_slice(&block);
        }

        let out = *byte ^ stream[*position];
        if encrypt {
            feedback[*position] = out;
        } else {
            feedback[*position] = *byte;
        }

        output.push(out);
        *position = (*position + 1) % feedback.len();
    }

    output
}

fn biguint_to_fixed_len(value: BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= len {
        return bytes[bytes.len() - len..].to_vec();
    }

    let mut out = vec![0; len - bytes.len()];
    out.extend(bytes);
    out
}

#[cfg(test)]
mod tests {
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    use super::*;

    fn rsa_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap()
    }

    fn random_fill(seed: u8) -> impl FnMut(&mut [u8]) {
        move |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seed.wrapping_add(index as u8);
            }
        }
    }

    fn message_id_name(message: &MetaMessage) -> Option<&str> {
        match message {
            MetaMessage::Id(message) => Some(&message.name),
            _ => None,
        }
    }

    #[test]
    fn legacy_meta_cipher_nids_match_tinc_aes_cfb_table() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Some(LegacyMetaCipherAlgorithm::Aes128Cfb),
            LegacyMetaCipherAlgorithm::from_nid(421)
        );
        assert_eq!(
            Some(LegacyMetaCipherAlgorithm::Aes192Cfb),
            LegacyMetaCipherAlgorithm::from_nid(425)
        );
        assert_eq!(
            Some(LegacyMetaCipherAlgorithm::Aes256Cfb),
            LegacyMetaCipherAlgorithm::from_nid(429)
        );
        assert_eq!(None, LegacyMetaCipherAlgorithm::from_nid(427));
        assert_eq!(
            LegacyMetaCipherAlgorithm::Aes128Cfb,
            LegacyMetaCipherAlgorithm::for_plain_key_len(16)
        );
        assert_eq!(
            LegacyMetaCipherAlgorithm::Aes192Cfb,
            LegacyMetaCipherAlgorithm::for_plain_key_len(24)
        );
        assert_eq!(
            LegacyMetaCipherAlgorithm::Aes256Cfb,
            LegacyMetaCipherAlgorithm::for_plain_key_len(32)
        );
    }

    #[test]
    fn legacy_meta_uses_c_rsa_no_padding_and_fixed_width_blocks() {
        tinc_test_support::assert_can_create_netns();
        let private = rsa_key();
        let public = RsaPublicKey::from(&private);
        let size = rsa_size(&public);
        let plaintext = legacy_meta_generate_rsa_key_material(size, |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (255 - index % 251) as u8;
            }
        })
        .unwrap();

        assert_eq!(0, plaintext[0] & 0x80);

        let encrypted = legacy_meta_public_encrypt(&public, &plaintext).unwrap();
        assert_eq!(size, encrypted.len());
        assert_ne!(plaintext, encrypted);
        assert_eq!(
            plaintext,
            legacy_meta_private_decrypt_pem(&private, &encrypted).unwrap()
        );
    }

    #[test]
    fn legacy_meta_can_decrypt_c_legacy_hex_private_components() {
        tinc_test_support::assert_can_create_netns();
        let private = RsaPrivateKey::new_with_exp(
            &mut rsa::rand_core::OsRng,
            1024,
            &BigUint::from(0xffffu32),
        )
        .unwrap();
        let public = RsaPublicKey::from(&private);
        let size = rsa_size(&public);
        let mut plaintext = vec![0x55; size];
        plaintext[0] &= 0x7f;

        let encrypted = legacy_meta_public_encrypt(&public, &plaintext).unwrap();
        assert_eq!(
            plaintext,
            legacy_meta_private_decrypt_components(&public, private.d(), &encrypted).unwrap()
        );
        assert_eq!(BigUint::from(0xffffu32), *public.e());
    }

    #[test]
    fn legacy_meta_cipher_key_and_iv_are_taken_from_rsa_tail_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let material = (0..128).map(|value| value as u8).collect::<Vec<_>>();
        let (key, iv) =
            legacy_meta_key_iv_from_rsa(LegacyMetaCipherAlgorithm::Aes256Cfb, &material).unwrap();

        assert_eq!(&material[80..96], iv);
        assert_eq!(&material[96..128], key);
    }

    #[test]
    fn legacy_meta_auth_follows_c_rsa_handshake_order() {
        tinc_test_support::assert_can_create_netns();
        let alice_private = rsa_key();
        let bob_private = rsa_key();
        let alice_public = RsaPublicKey::from(&alice_private);
        let bob_public = RsaPublicKey::from(&bob_private);
        let alice_size = rsa_size(&alice_public);
        let bob_size = rsa_size(&bob_public);
        let mut alice = LegacyMetaAuth::new(
            "alice",
            true,
            LegacyMetaPrivateKey::Pem(alice_private),
            bob_public.clone(),
            "655",
            10,
            OPTION_PMTU_DISCOVERY,
        )
        .with_mac_length(7);
        let mut bob = LegacyMetaAuth::new(
            "bob",
            false,
            LegacyMetaPrivateKey::Pem(bob_private),
            alice_public.clone(),
            "655",
            20,
            0,
        );

        let alice_id = alice.local_id_message();
        assert_eq!(
            "0 alice 17.0\n",
            String::from_utf8(legacy_meta_encode_line(&alice_id)).unwrap()
        );

        let bob_after_id = bob
            .receive_meta_message_with_random(&alice_id, random_fill(0x10))
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectMetaKey, bob.state());
        assert_eq!(2, bob_after_id.outbound.len());
        assert_eq!(
            Some("bob"),
            message_id_name(&bob_after_id.outbound[0].message)
        );
        assert!(!bob_after_id.outbound[0].encrypted);
        assert!(!bob_after_id.outbound[1].encrypted);
        assert!(bob.outbound_encrypted());
        let MetaMessage::MetaKey(bob_metakey) = &bob_after_id.outbound[1].message else {
            panic!("incoming side should send METAKEY after ID");
        };
        assert_eq!(
            LegacyMetaCipherAlgorithm::Aes256Cfb.nid(),
            bob_metakey.cipher
        );
        assert_eq!(LEGACY_META_DEFAULT_DIGEST_NID, bob_metakey.digest);
        assert_eq!(LEGACY_META_DEFAULT_MAC_LENGTH, bob_metakey.mac_length);
        assert_eq!(LEGACY_META_COMPRESS_NONE, bob_metakey.compression);
        assert_eq!(alice_size * 2, bob_metakey.key.len());

        let alice_after_id = alice
            .receive_meta_message_with_random(&bob_after_id.outbound[0].message, random_fill(0x20))
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectMetaKey, alice.state());
        assert_eq!(1, alice_after_id.outbound.len());
        assert!(!alice_after_id.outbound[0].encrypted);
        let MetaMessage::MetaKey(alice_metakey) = &alice_after_id.outbound[0].message else {
            panic!("outgoing side should send METAKEY after peer ID");
        };
        assert_eq!(7, alice_metakey.mac_length);
        assert_eq!(bob_size * 2, alice_metakey.key.len());

        let bob_after_metakey = bob
            .receive_meta_message_with_random(
                &alice_after_id.outbound[0].message,
                random_fill(0x30),
            )
            .unwrap();
        assert!(bob.inbound_encrypted());
        assert_eq!(LegacyMetaAuthState::ExpectChallenge, bob.state());
        assert_eq!(1, bob_after_metakey.outbound.len());
        let bob_challenge = bob_after_metakey.outbound[0].clone();
        assert!(bob_challenge.encrypted);
        let MetaMessage::Challenge(bob_challenge_message) = &bob_challenge.message else {
            panic!("METAKEY handler should send CHALLENGE");
        };
        assert_eq!(alice_size * 2, bob_challenge_message.data.len());

        let alice_after_metakey = alice
            .receive_meta_message_with_random(&bob_after_id.outbound[1].message, random_fill(0x40))
            .unwrap();
        assert!(alice.inbound_encrypted());
        assert_eq!(LegacyMetaAuthState::ExpectChallenge, alice.state());
        let alice_challenge = alice_after_metakey.outbound[0].clone();
        let MetaMessage::Challenge(alice_challenge_message) = &alice_challenge.message else {
            panic!("METAKEY handler should send CHALLENGE");
        };
        assert_eq!(bob_size * 2, alice_challenge_message.data.len());

        let bob_challenge_line = legacy_meta_encode_line(&bob_challenge.message);
        let encrypted_bob_challenge = bob.encode_outbound_message(&bob_challenge).unwrap();
        assert_ne!(bob_challenge_line, encrypted_bob_challenge);
        assert_eq!(
            bob_challenge_line,
            alice.decrypt_inbound(&encrypted_bob_challenge).unwrap()
        );

        let alice_after_challenge = alice
            .receive_meta_message_with_random(&bob_challenge.message, random_fill(0x50))
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectChallengeReply, alice.state());
        assert_eq!(1, alice_after_challenge.outbound.len());
        let alice_chal_reply = alice_after_challenge.outbound[0].clone();
        assert!(alice_chal_reply.encrypted);
        let MetaMessage::ChallengeReply(alice_chal_reply_message) = &alice_chal_reply.message
        else {
            panic!("outgoing side should answer CHALLENGE immediately");
        };
        let bob_challenge = hex_to_bin(&bob_challenge_message.data, alice_size);
        let sha256 =
            LegacyMetaDigest::from_nid_and_length(LEGACY_META_DEFAULT_DIGEST_NID, usize::MAX)
                .unwrap();
        assert_eq!(
            sha256.create_hex(&bob_challenge),
            alice_chal_reply_message.digest
        );

        let bob_after_challenge = bob
            .receive_meta_message_with_random(&alice_challenge.message, random_fill(0x60))
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectChallengeReply, bob.state());
        assert!(bob_after_challenge.outbound.is_empty());

        let bob_after_chal_reply = bob
            .receive_meta_message_with_random(&alice_chal_reply.message, random_fill(0x70))
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectAck, bob.state());
        assert_eq!(2, bob_after_chal_reply.outbound.len());
        assert!(matches!(
            bob_after_chal_reply.outbound.as_slice(),
            [
                LegacyMetaOutboundMessage {
                    message: MetaMessage::ChallengeReply(_),
                    encrypted: true
                },
                LegacyMetaOutboundMessage {
                    message: MetaMessage::Ack(AckMessage::Connection { .. }),
                    encrypted: true
                }
            ]
        ));

        let alice_after_chal_reply = alice
            .receive_meta_message_with_random(
                &bob_after_chal_reply.outbound[0].message,
                random_fill(0x80),
            )
            .unwrap();
        assert_eq!(LegacyMetaAuthState::ExpectAck, alice.state());
        assert_eq!(1, alice_after_chal_reply.outbound.len());
        assert!(matches!(
            alice_after_chal_reply.outbound[0],
            LegacyMetaOutboundMessage {
                message: MetaMessage::Ack(AckMessage::Connection { .. }),
                encrypted: true
            }
        ));

        let alice_done = alice
            .receive_meta_message_with_random(
                &bob_after_chal_reply.outbound[1].message,
                random_fill(0x90),
            )
            .unwrap();
        assert_eq!(LegacyMetaAuthState::Activated, alice.state());
        assert_eq!(
            vec![LegacyMetaAuthEvent::Activated {
                peer: "bob".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: 0,
            }],
            alice_done.events
        );

        let bob_done = bob
            .receive_meta_message_with_random(
                &alice_after_chal_reply.outbound[0].message,
                random_fill(0xa0),
            )
            .unwrap();
        assert_eq!(LegacyMetaAuthState::Activated, bob.state());
        assert_eq!(
            vec![LegacyMetaAuthEvent::Activated {
                peer: "alice".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: 0,
            }],
            bob_done.events
        );
    }

    #[test]
    fn legacy_meta_auth_rejects_modern_minor_like_c_dispatch_boundary() {
        tinc_test_support::assert_can_create_netns();
        let private = rsa_key();
        let public = RsaPublicKey::from(&private);
        let mut auth = LegacyMetaAuth::new(
            "alice",
            false,
            LegacyMetaPrivateKey::Pem(private),
            public,
            "655",
            10,
            0,
        );
        let id = MetaMessage::Id(IdMessage {
            name: "bob".to_owned(),
            protocol_major: PROT_MAJOR as i32,
            protocol_minor: Some(2),
        });

        assert_eq!(
            Err(LegacyMetaAuthError::UnsupportedProtocolMinor(2)),
            auth.receive_meta_message_with_random(&id, random_fill(0x11))
        );
    }

    #[test]
    fn legacy_meta_connection_driver_handles_c_plain_then_encrypted_stream() {
        tinc_test_support::assert_can_create_netns();
        let alice_private = rsa_key();
        let bob_private = rsa_key();
        let alice_public = RsaPublicKey::from(&alice_private);
        let bob_public = RsaPublicKey::from(&bob_private);
        let mut alice = LegacyMetaConnectionDriver::new(LegacyMetaAuth::new(
            "alice",
            true,
            LegacyMetaPrivateKey::Pem(alice_private),
            bob_public,
            "655",
            10,
            0,
        ));
        let mut bob = LegacyMetaConnectionDriver::new(LegacyMetaAuth::new(
            "bob",
            false,
            LegacyMetaPrivateKey::Pem(bob_private),
            alice_public,
            "655",
            20,
            0,
        ));

        let bob_after_id = bob.receive_bytes(&alice.initial_id_bytes()).unwrap();
        assert_eq!(2, bob_after_id.outbound.len());
        assert_eq!(
            "0 bob 17.0\n",
            String::from_utf8(bob_after_id.outbound[0].clone()).unwrap()
        );
        assert!(
            String::from_utf8(bob_after_id.outbound[1].clone())
                .unwrap()
                .starts_with("1 429 672 4 0 ")
        );
        assert!(bob.auth().outbound_encrypted());
        assert!(!bob.auth().inbound_encrypted());

        let mut bob_id_and_metakey = Vec::new();
        bob_id_and_metakey.extend_from_slice(&bob_after_id.outbound[0]);
        bob_id_and_metakey.extend_from_slice(&bob_after_id.outbound[1]);
        let alice_after_id_and_metakey = alice.receive_bytes(&bob_id_and_metakey).unwrap();
        assert!(alice.auth().outbound_encrypted());
        assert!(alice.auth().inbound_encrypted());
        assert_eq!(2, alice_after_id_and_metakey.outbound.len());
        assert!(
            String::from_utf8(alice_after_id_and_metakey.outbound[0].clone())
                .unwrap()
                .starts_with("1 429 672 4 0 ")
        );
        assert!(String::from_utf8(alice_after_id_and_metakey.outbound[1].clone()).is_err());

        let mut alice_metakey_and_challenge = Vec::new();
        alice_metakey_and_challenge.extend_from_slice(&alice_after_id_and_metakey.outbound[0]);
        alice_metakey_and_challenge.extend_from_slice(&alice_after_id_and_metakey.outbound[1]);
        let bob_after_alice_metakey_and_challenge =
            bob.receive_bytes(&alice_metakey_and_challenge).unwrap();
        assert!(bob.auth().inbound_encrypted());
        assert_eq!(1, bob_after_alice_metakey_and_challenge.outbound.len());
        assert!(
            String::from_utf8(bob_after_alice_metakey_and_challenge.outbound[0].clone()).is_err()
        );

        let alice_after_bob_challenge = alice
            .receive_bytes(&bob_after_alice_metakey_and_challenge.outbound.concat())
            .unwrap();
        assert_eq!(1, alice_after_bob_challenge.outbound.len());
        let bob_after_alice_reply = bob
            .receive_bytes(&alice_after_bob_challenge.outbound.concat())
            .unwrap();
        assert_eq!(2, bob_after_alice_reply.outbound.len());

        let alice_after_bob_reply_and_ack = alice
            .receive_bytes(&bob_after_alice_reply.outbound.concat())
            .unwrap();
        assert_eq!(LegacyMetaAuthState::Activated, alice.auth().state());
        assert_eq!(1, alice_after_bob_reply_and_ack.outbound.len());
        assert!(matches!(
            alice_after_bob_reply_and_ack.events.as_slice(),
            [MetaConnectionEvent::Message(MetaMessage::ChallengeReply(_)),
             MetaConnectionEvent::Message(MetaMessage::Ack(_)),
             MetaConnectionEvent::Auth(MetaAuthEvent::Activated { peer, .. })]
                if peer == "bob"
        ));

        let bob_after_alice_ack = bob
            .receive_bytes(&alice_after_bob_reply_and_ack.outbound.concat())
            .unwrap();
        assert_eq!(LegacyMetaAuthState::Activated, bob.auth().state());
        assert!(matches!(
            bob_after_alice_ack.events.as_slice(),
            [MetaConnectionEvent::Message(MetaMessage::Ack(_)),
             MetaConnectionEvent::Auth(MetaAuthEvent::Activated { peer, .. })]
                if peer == "alice"
        ));

        let wire = alice.send_tcp_packet(b"pong").unwrap().concat();
        assert!(String::from_utf8(wire.clone()).is_err());
        let bob_packet = bob.receive_bytes(&wire).unwrap();
        assert_eq!(
            vec![
                MetaConnectionEvent::Message(MetaMessage::TcpPacket(TcpPacketMessage {
                    length: 4
                })),
                MetaConnectionEvent::TcpPacket(b"pong".to_vec())
            ],
            bob_packet.events
        );
    }

    #[test]
    fn legacy_meta_connection_driver_handles_minor_one_ed25519_upgrade_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let alice_private = rsa_key();
        let bob_private = rsa_key();
        let alice_public = RsaPublicKey::from(&alice_private);
        let bob_public = RsaPublicKey::from(&bob_private);
        let mut alice = LegacyMetaConnectionDriver::new(
            LegacyMetaAuth::new(
                "alice",
                true,
                LegacyMetaPrivateKey::Pem(alice_private),
                bob_public,
                "655",
                10,
                0,
            )
            .with_protocol_minor(LEGACY_META_UPGRADE_PROTOCOL_MINOR)
            .with_upgrade_public_key("alice-ed25519"),
        );
        let mut bob = LegacyMetaConnectionDriver::new(
            LegacyMetaAuth::new(
                "bob",
                false,
                LegacyMetaPrivateKey::Pem(bob_private),
                alice_public,
                "655",
                20,
                0,
            )
            .with_protocol_minor(tinc_core::protocol::PROT_MINOR as i32)
            .with_upgrade_public_key("bob-ed25519"),
        );

        assert_eq!(
            "0 alice 17.1\n",
            String::from_utf8(alice.initial_id_bytes()).unwrap()
        );
        let bob_after_id = bob.receive_bytes(&alice.initial_id_bytes()).unwrap();
        assert_eq!(
            format!("0 bob 17.{}\n", tinc_core::protocol::PROT_MINOR),
            String::from_utf8(bob_after_id.outbound[0].clone()).unwrap()
        );

        let alice_after_id = alice
            .receive_bytes(&bob_after_id.outbound.concat())
            .unwrap();
        let bob_after_metakey = bob
            .receive_bytes(&alice_after_id.outbound.concat())
            .unwrap();
        let alice_after_challenge = alice
            .receive_bytes(&bob_after_metakey.outbound.concat())
            .unwrap();
        let bob_after_reply = bob
            .receive_bytes(&alice_after_challenge.outbound.concat())
            .unwrap();

        let alice_after_upgrade = alice
            .receive_bytes(&bob_after_reply.outbound.concat())
            .unwrap();
        assert_eq!(
            LegacyMetaAuthState::UpgradeTerminating,
            alice.auth().state()
        );
        assert!(!alice_after_upgrade.outbound.is_empty());
        assert!(matches!(
            alice_after_upgrade.events.as_slice(),
            [MetaConnectionEvent::Message(MetaMessage::ChallengeReply(_)),
             MetaConnectionEvent::Message(MetaMessage::Ack(AckMessage::Payload(public_key))),
             MetaConnectionEvent::Auth(MetaAuthEvent::LegacyEd25519Upgrade { peer, public_key: event_key })]
                if public_key == "bob-ed25519" && peer == "bob" && event_key == "bob-ed25519"
        ));

        let bob_after_upgrade = bob
            .receive_bytes(&alice_after_upgrade.outbound.concat())
            .unwrap();
        assert_eq!(LegacyMetaAuthState::UpgradeTerminating, bob.auth().state());
        assert!(matches!(
            bob_after_upgrade.events.as_slice(),
            [MetaConnectionEvent::Message(MetaMessage::Ack(AckMessage::Payload(public_key))),
             MetaConnectionEvent::Auth(MetaAuthEvent::LegacyEd25519Upgrade { peer, public_key: event_key }),
             MetaConnectionEvent::Message(MetaMessage::TerminateRequest)]
                if public_key == "alice-ed25519" && peer == "alice" && event_key == "alice-ed25519"
        ));
        assert!(!bob_after_upgrade.events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Auth(MetaAuthEvent::Activated { .. })
            )
        }));
    }

    #[test]
    fn legacy_meta_aes_cfb_roundtrips_stream_chunks() {
        tinc_test_support::assert_can_create_netns();
        let material = (0..128).map(|value| value as u8).collect::<Vec<_>>();
        let mut encrypt = LegacyMetaCipher::from_rsa_key_material(
            LegacyMetaCipherAlgorithm::Aes256Cfb,
            &material,
        )
        .unwrap();
        let mut decrypt = LegacyMetaCipher::from_rsa_key_material(
            LegacyMetaCipherAlgorithm::Aes256Cfb,
            &material,
        )
        .unwrap();

        let first = encrypt.apply_encrypt(b"hello ").unwrap();
        let second = encrypt.apply_encrypt(b"legacy meta").unwrap();

        assert_eq!(b"hello ", decrypt.apply_decrypt(&first).unwrap().as_slice());
        assert_eq!(
            b"legacy meta",
            decrypt.apply_decrypt(&second).unwrap().as_slice()
        );
    }

    #[test]
    fn legacy_meta_challenge_reply_uses_plain_digest_not_hmac() {
        tinc_test_support::assert_can_create_netns();
        let digest =
            LegacyMetaDigest::from_nid_and_length(LEGACY_META_DEFAULT_DIGEST_NID, usize::MAX)
                .unwrap();
        let challenge = b"abc";

        assert_eq!(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            digest.create_hex(challenge)
        );
        digest
            .verify_hex(
                challenge,
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            )
            .unwrap();
        assert!(matches!(
            digest.verify_hex(
                challenge,
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            Err(LegacyMetaError::DigestMismatch)
        ));
    }
}

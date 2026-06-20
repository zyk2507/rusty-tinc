// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
#[cfg(feature = "lzo")]
use std::sync::OnceLock;

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use flate2::Compression as ZlibCompression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use hmac::{Hmac, Mac};
#[cfg(feature = "openssl-legacy")]
use openssl::hash::MessageDigest as OpensslMessageDigest;
#[cfg(feature = "openssl-legacy")]
use openssl::nid::Nid;
#[cfg(feature = "openssl-legacy")]
use openssl::pkey::PKey;
#[cfg(feature = "openssl-legacy")]
use openssl::sign::Signer as OpensslSigner;
#[cfg(feature = "openssl-legacy")]
use openssl::symm::{Cipher as OpensslCipher, Mode as OpensslCipherMode};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use tinc_core::graph::{NODE_ID_LEN, NodeId};
use tinc_core::protocol::AnswerKeyMessage;
use tinc_core::route::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6};
use tinc_core::state::NetworkState;
use tinc_core::utils::hex_to_bin;

use crate::device::{DeviceError, MTU, VpnPacket};
use crate::engine::{PacketReceiver, PacketTransport, TransportError};
use crate::sptps::{
    SPTPS_HANDSHAKE, SptpsDatagramCodec, SptpsError, SptpsHandshakeEvent, SptpsHandshakeSession,
    SptpsKey, SptpsRecord,
};

pub const RELAY_HEADER_LEN: usize = NODE_ID_LEN * 2;
pub const LEGACY_SEQNO_LEN: usize = 4;
pub const LEGACY_CIPHER_MAX_BLOCK_SIZE: usize = 32;
pub const LEGACY_DIGEST_MAX_SIZE: usize = 64;
pub const LEGACY_COMPRESSION_OVERHEAD: usize = MTU / 64 + 20;
pub const MAX_DATAGRAM_SIZE: usize = MTU
    + LEGACY_SEQNO_LEN
    + RELAY_HEADER_LEN
    + LEGACY_CIPHER_MAX_BLOCK_SIZE
    + LEGACY_DIGEST_MAX_SIZE
    + LEGACY_COMPRESSION_OVERHEAD;
pub const MAX_META_BUFFER_SIZE: usize = if MAX_DATAGRAM_SIZE > 2048 {
    MAX_DATAGRAM_SIZE + 128
} else {
    2048 + 128
};
pub const DEFAULT_REPLAY_WINDOW_BYTES: usize = 32;
pub const MAX_LEGACY_SEQNO: u32 = 1_073_741_824;
pub const SPTPS_PACKET_TYPE_MAC: u8 = 0x02;

pub trait PacketCodec {
    fn encode(&mut self, target: &str, packet: &VpnPacket) -> Result<Vec<u8>, TransportError>;
    fn decode(&mut self, source: &str, datagram: &[u8]) -> Result<VpnPacket, TransportError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlainPacketCodec;

impl PacketCodec for PlainPacketCodec {
    fn encode(&mut self, _target: &str, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        Ok(packet.data.clone())
    }

    fn decode(&mut self, _source: &str, datagram: &[u8]) -> Result<VpnPacket, TransportError> {
        VpnPacket::new(datagram.to_vec()).map_err(TransportError::from)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CompressionLevel {
    None = 0,
    Zlib1 = 1,
    Zlib2 = 2,
    Zlib3 = 3,
    Zlib4 = 4,
    Zlib5 = 5,
    Zlib6 = 6,
    Zlib7 = 7,
    Zlib8 = 8,
    Zlib9 = 9,
    LzoLow = 10,
    LzoHigh = 11,
    Lz4 = 12,
}

impl TryFrom<i32> for CompressionLevel {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zlib1),
            2 => Ok(Self::Zlib2),
            3 => Ok(Self::Zlib3),
            4 => Ok(Self::Zlib4),
            5 => Ok(Self::Zlib5),
            6 => Ok(Self::Zlib6),
            7 => Ok(Self::Zlib7),
            8 => Ok(Self::Zlib8),
            9 => Ok(Self::Zlib9),
            10 => Ok(Self::LzoLow),
            11 => Ok(Self::LzoHigh),
            12 => Ok(Self::Lz4),
            _ => Err(value),
        }
    }
}

impl CompressionLevel {
    pub const fn zlib_level(self) -> Option<u32> {
        match self {
            Self::Zlib1 => Some(1),
            Self::Zlib2 => Some(2),
            Self::Zlib3 => Some(3),
            Self::Zlib4 => Some(4),
            Self::Zlib5 => Some(5),
            Self::Zlib6 => Some(6),
            Self::Zlib7 => Some(7),
            Self::Zlib8 => Some(8),
            Self::Zlib9 => Some(9),
            _ => None,
        }
    }
}

const AES_BLOCK_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LegacyCipherAlgorithm {
    #[default]
    None,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Unsupported(i32),
}

impl LegacyCipherAlgorithm {
    pub fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("none") {
            return Some(Self::None);
        }
        if name.eq_ignore_ascii_case("aes-128-cbc") {
            return Some(Self::Aes128Cbc);
        }
        if name.eq_ignore_ascii_case("aes-192-cbc") {
            return Some(Self::Aes192Cbc);
        }
        if name.eq_ignore_ascii_case("aes-256-cbc") {
            return Some(Self::Aes256Cbc);
        }

        openssl_cipher_nid_from_name(name).map(Self::from_nid)
    }

    pub fn from_nid(nid: i32) -> Self {
        match nid {
            nid if nid <= 0 => Self::None,
            419 => Self::Aes128Cbc,
            423 => Self::Aes192Cbc,
            427 => Self::Aes256Cbc,
            _ => Self::Unsupported(nid),
        }
    }

    pub const fn nid(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Aes128Cbc => 419,
            Self::Aes192Cbc => 423,
            Self::Aes256Cbc => 427,
            Self::Unsupported(nid) => nid,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc => 24,
            Self::Aes256Cbc => 32,
            Self::Unsupported(nid) => openssl_cipher_key_len(nid),
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => AES_BLOCK_LEN,
            Self::Unsupported(nid) => openssl_cipher_iv_len(nid),
        }
    }

    pub fn key_material_len(self) -> usize {
        self.key_len() + self.iv_len()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyCipher {
    algorithm: LegacyCipherAlgorithm,
    key_material: Vec<u8>,
}

impl LegacyCipher {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn from_nid(nid: i32) -> Self {
        Self::new(LegacyCipherAlgorithm::from_nid(nid), Vec::new())
    }

    pub fn new(algorithm: LegacyCipherAlgorithm, key_material: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm,
            key_material: key_material.into(),
        }
    }

    pub fn from_nid_key(nid: i32, key_material: impl Into<Vec<u8>>) -> Self {
        Self::new(LegacyCipherAlgorithm::from_nid(nid), key_material)
    }

    pub const fn algorithm(&self) -> LegacyCipherAlgorithm {
        self.algorithm
    }

    pub fn key_material(&self) -> &[u8] {
        &self.key_material
    }

    pub fn set_key(&mut self, key_material: impl Into<Vec<u8>>) {
        self.key_material = key_material.into();
    }

    pub fn key_material_len(&self) -> usize {
        self.algorithm.key_material_len()
    }

    fn encrypt(&self, packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        match self.algorithm {
            LegacyCipherAlgorithm::None => Ok(packet.to_vec()),
            LegacyCipherAlgorithm::Aes128Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                Ok(cbc::Encryptor::<Aes128>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(packet))
            }
            LegacyCipherAlgorithm::Aes192Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                Ok(cbc::Encryptor::<Aes192>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(packet))
            }
            LegacyCipherAlgorithm::Aes256Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                Ok(cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(packet))
            }
            LegacyCipherAlgorithm::Unsupported(nid) => {
                openssl_cipher_crypt(nid, &self.key_material, packet, true)
            }
        }
    }

    fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        match self.algorithm {
            LegacyCipherAlgorithm::None => Ok(packet.to_vec()),
            LegacyCipherAlgorithm::Aes128Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(packet)
                    .map_err(|error| LegacyPacketError::CipherFailed {
                        nid: self.algorithm.nid(),
                        message: error.to_string(),
                    })
            }
            LegacyCipherAlgorithm::Aes192Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                cbc::Decryptor::<Aes192>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(packet)
                    .map_err(|error| LegacyPacketError::CipherFailed {
                        nid: self.algorithm.nid(),
                        message: error.to_string(),
                    })
            }
            LegacyCipherAlgorithm::Aes256Cbc => {
                let (key, iv) = self.aes_key_iv()?;
                cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(packet)
                    .map_err(|error| LegacyPacketError::CipherFailed {
                        nid: self.algorithm.nid(),
                        message: error.to_string(),
                    })
            }
            LegacyCipherAlgorithm::Unsupported(nid) => {
                openssl_cipher_crypt(nid, &self.key_material, packet, false)
            }
        }
    }

    fn aes_key_iv(&self) -> Result<(&[u8], &[u8]), LegacyPacketError> {
        let expected = self.algorithm.key_material_len();

        if self.key_material.len() != expected {
            return Err(LegacyPacketError::InvalidCipherKeyLength {
                nid: self.algorithm.nid(),
                expected,
                actual: self.key_material.len(),
            });
        }

        let key_len = self.algorithm.key_len();
        Ok(self.key_material.split_at(key_len))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LegacyDigest {
    #[default]
    None,
    Sha1 {
        length: usize,
    },
    Sha256 {
        length: usize,
    },
    Sha384 {
        length: usize,
    },
    Sha512 {
        length: usize,
    },
    Unsupported {
        nid: i32,
        length: usize,
    },
}

impl LegacyDigest {
    pub fn from_name_and_length(name: &str, length: usize) -> Option<Self> {
        if name.eq_ignore_ascii_case("none") {
            return Some(Self::None);
        }
        if name.eq_ignore_ascii_case("sha1") || name.eq_ignore_ascii_case("sha-1") {
            return Some(Self::from_nid_and_length(64, length));
        }
        if name.eq_ignore_ascii_case("sha256") || name.eq_ignore_ascii_case("sha-256") {
            return Some(Self::from_nid_and_length(672, length));
        }
        if name.eq_ignore_ascii_case("sha384") || name.eq_ignore_ascii_case("sha-384") {
            return Some(Self::from_nid_and_length(673, length));
        }
        if name.eq_ignore_ascii_case("sha512") || name.eq_ignore_ascii_case("sha-512") {
            return Some(Self::from_nid_and_length(674, length));
        }

        openssl_digest_nid_from_name(name).map(|nid| Self::from_nid_and_length(nid, length))
    }

    pub fn from_nid_and_length(nid: i32, length: usize) -> Self {
        if nid <= 0 {
            return Self::None;
        }

        let length = Self::effective_length_for_nid(nid, length);

        match nid {
            64 => Self::Sha1 { length },
            672 => Self::Sha256 { length },
            673 => Self::Sha384 { length },
            674 => Self::Sha512 { length },
            _ => Self::Unsupported { nid, length },
        }
    }

    fn effective_length_for_nid(nid: i32, requested: usize) -> usize {
        match Self::maximum_length_for_nid(nid) {
            Some(maximum) if requested == usize::MAX || requested > maximum => maximum,
            _ => requested,
        }
    }

    fn maximum_length_for_nid(nid: i32) -> Option<usize> {
        match nid {
            64 => Some(20),
            672 => Some(32),
            673 => Some(48),
            674 => Some(64),
            _ => openssl_digest_len(nid),
        }
    }

    pub const fn nid(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Sha1 { .. } => 64,
            Self::Sha256 { .. } => 672,
            Self::Sha384 { .. } => 673,
            Self::Sha512 { .. } => 674,
            Self::Unsupported { nid, .. } => nid,
        }
    }

    pub fn with_key(self, key: impl Into<Vec<u8>>) -> LegacyDigestState {
        LegacyDigestState::new(self, key)
    }

    fn create(self, key: &[u8], packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        let mut mac = match self {
            Self::None => return Ok(Vec::new()),
            Self::Sha1 { .. } => hmac_sha1(key, packet),
            Self::Sha256 { .. } => hmac_sha256(key, packet),
            Self::Sha384 { .. } => hmac_sha384(key, packet),
            Self::Sha512 { .. } => hmac_sha512(key, packet),
            Self::Unsupported { nid, length } => openssl_hmac(nid, key, packet)
                .ok_or(LegacyPacketError::UnsupportedDigest { nid, length }),
        }?;

        mac.truncate(self.length());
        Ok(mac)
    }

    fn verify(self, key: &[u8], packet: &[u8], expected: &[u8]) -> Result<(), LegacyPacketError> {
        let actual = self.create(key, packet)?;

        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(LegacyPacketError::DigestMismatch {
                nid: self.nid(),
                length: self.length(),
            })
        }
    }

    pub const fn length(self) -> usize {
        match self {
            Self::None => 0,
            Self::Sha1 { length }
            | Self::Sha256 { length }
            | Self::Sha384 { length }
            | Self::Sha512 { length } => length,
            Self::Unsupported { length, .. } => length,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyDigestState {
    algorithm: LegacyDigest,
    key: Vec<u8>,
}

impl LegacyDigestState {
    pub fn new(algorithm: LegacyDigest, key: impl Into<Vec<u8>>) -> Self {
        let key = key.into();

        Self { algorithm, key }
    }

    pub fn from_nid_length_key(nid: i32, length: usize, key: impl Into<Vec<u8>>) -> Self {
        LegacyDigest::from_nid_and_length(nid, length).with_key(key)
    }

    pub const fn algorithm(&self) -> LegacyDigest {
        self.algorithm
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn set_key(&mut self, key: impl Into<Vec<u8>>) {
        self.key = key.into();
    }

    pub const fn length(&self) -> usize {
        self.algorithm.length()
    }

    fn append(&self, packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        if self.algorithm == LegacyDigest::None {
            return Ok(packet.to_vec());
        }

        let mut out = Vec::with_capacity(packet.len() + self.length());
        out.extend_from_slice(packet);
        out.extend_from_slice(&self.algorithm.create(&self.key, packet)?);
        Ok(out)
    }

    fn verify_and_strip<'a>(&self, packet: &'a [u8]) -> Result<&'a [u8], LegacyPacketError> {
        if self.algorithm == LegacyDigest::None {
            return Ok(packet);
        }

        let length = self.length();

        if packet.len() < length {
            return Err(LegacyPacketError::PacketTooShort {
                minimum: length,
                actual: packet.len(),
            });
        }

        let (body, mac) = packet.split_at(packet.len() - length);
        self.algorithm.verify(&self.key, body, mac)?;
        Ok(body)
    }

    fn verify_active_packet(&self, packet: &[u8]) -> Result<(), LegacyPacketError> {
        if self.algorithm == LegacyDigest::None {
            return Err(LegacyPacketError::DigestMismatch {
                nid: self.algorithm.nid(),
                length: self.length(),
            });
        }

        self.verify_and_strip(packet).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyPacketDirection {
    pub compression: CompressionLevel,
    pub cipher: LegacyCipher,
    pub digest: LegacyDigestState,
}

impl LegacyPacketDirection {
    pub fn new(
        compression: CompressionLevel,
        cipher: LegacyCipher,
        digest: LegacyDigestState,
    ) -> Self {
        Self {
            compression,
            cipher,
            digest,
        }
    }

    pub fn from_legacy_answer_key(message: &AnswerKeyMessage) -> Result<Self, LegacyPacketError> {
        let compression = CompressionLevel::try_from(message.compression)
            .map_err(LegacyPacketError::InvalidCompression)?;
        if compression_is_unavailable(compression) {
            return Err(LegacyPacketError::UnsupportedCompression(compression));
        }
        let cipher_algorithm = LegacyCipherAlgorithm::from_nid(message.cipher);

        if let LegacyCipherAlgorithm::Unsupported(nid) = cipher_algorithm {
            return Err(LegacyPacketError::UnsupportedCipher(nid));
        }

        let requested_mac_length = usize::try_from(message.mac_length).unwrap_or(usize::MAX);
        let digest_algorithm =
            LegacyDigest::from_nid_and_length(message.digest, requested_mac_length);

        if let LegacyDigest::Unsupported { nid, length } = digest_algorithm {
            return Err(LegacyPacketError::UnsupportedDigest { nid, length });
        }

        if requested_mac_length != usize::MAX && requested_mac_length != digest_algorithm.length() {
            return Err(LegacyPacketError::InvalidDigestLength {
                nid: digest_algorithm.nid(),
                requested: requested_mac_length,
                actual: digest_algorithm.length(),
            });
        }

        let expected_key_len = if cipher_algorithm == LegacyCipherAlgorithm::None {
            1
        } else {
            cipher_algorithm.key_material_len()
        };
        let key = hex_to_bin(&message.key, expected_key_len);

        if key.len() != expected_key_len {
            return Err(LegacyPacketError::InvalidKeyMaterialLength {
                expected: expected_key_len,
                actual: key.len(),
            });
        }

        let cipher_key = if cipher_algorithm == LegacyCipherAlgorithm::None {
            Vec::new()
        } else {
            key.clone()
        };

        Ok(Self {
            compression,
            cipher: LegacyCipher::new(cipher_algorithm, cipher_key),
            digest: digest_algorithm.with_key(key),
        })
    }

    pub fn without_crypto() -> Self {
        Self::default()
    }

    fn compress(&self, packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        if let Some(level) = self.compression.zlib_level() {
            return compress_zlib(packet, self.compression, level);
        }

        match self.compression {
            CompressionLevel::None => Ok(packet.to_vec()),
            CompressionLevel::Lz4 => Ok(lz4_flex::block::compress(packet)),
            CompressionLevel::LzoLow | CompressionLevel::LzoHigh => {
                compress_lzo(packet, self.compression)
            }
            compression => Err(LegacyPacketError::UnsupportedCompression(compression)),
        }
    }

    fn uncompress(&self, packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
        if self.compression.zlib_level().is_some() {
            return uncompress_zlib(packet, self.compression);
        }

        match self.compression {
            CompressionLevel::None => Ok(packet.to_vec()),
            CompressionLevel::Lz4 => uncompress_lz4(packet),
            CompressionLevel::LzoLow | CompressionLevel::LzoHigh => {
                uncompress_lzo(packet, self.compression)
            }
            compression => Err(LegacyPacketError::UnsupportedCompression(compression)),
        }
    }
}

impl Default for LegacyPacketDirection {
    fn default() -> Self {
        Self {
            compression: CompressionLevel::None,
            cipher: LegacyCipher::none(),
            digest: LegacyDigestState::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyPacketError {
    UnknownPeer(String),
    PacketTooShort {
        minimum: usize,
        actual: usize,
    },
    Replayed {
        seqno: u32,
        received_seqno: u32,
    },
    FarFuture {
        seqno: u32,
        received_seqno: u32,
        distance: u32,
        count: u32,
    },
    UnsupportedCompression(CompressionLevel),
    CompressionFailed {
        compression: CompressionLevel,
        message: String,
    },
    DecompressionFailed {
        compression: CompressionLevel,
        message: String,
    },
    UnsupportedCipher(i32),
    InvalidCipherKeyLength {
        nid: i32,
        expected: usize,
        actual: usize,
    },
    CipherFailed {
        nid: i32,
        message: String,
    },
    DigestMismatch {
        nid: i32,
        length: usize,
    },
    DigestFailed {
        nid: i32,
        message: String,
    },
    InvalidDigestLength {
        nid: i32,
        requested: usize,
        actual: usize,
    },
    UnsupportedDigest {
        nid: i32,
        length: usize,
    },
    InvalidCompression(i32),
    InvalidKeyMaterialLength {
        expected: usize,
        actual: usize,
    },
    Packet(DeviceError),
}

impl fmt::Display for LegacyPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPeer(peer) => write!(f, "unknown legacy UDP peer {peer}"),
            Self::PacketTooShort { minimum, actual } => {
                write!(
                    f,
                    "legacy UDP packet too short: expected at least {minimum}, got {actual}"
                )
            }
            Self::Replayed {
                seqno,
                received_seqno,
            } => write!(
                f,
                "late or replayed legacy UDP packet seqno {seqno}, last received {received_seqno}"
            ),
            Self::FarFuture {
                seqno,
                received_seqno,
                distance,
                count,
            } => write!(
                f,
                "legacy UDP packet seqno {seqno} is {distance} seqs in the future from {received_seqno} ({count})"
            ),
            Self::UnsupportedCompression(compression) => {
                write!(f, "unsupported legacy UDP compression {compression:?}")
            }
            Self::CompressionFailed {
                compression,
                message,
            } => write!(
                f,
                "legacy UDP compression {compression:?} failed: {message}"
            ),
            Self::DecompressionFailed {
                compression,
                message,
            } => write!(
                f,
                "legacy UDP decompression {compression:?} failed: {message}"
            ),
            Self::UnsupportedCipher(nid) => write!(f, "unsupported legacy UDP cipher NID {nid}"),
            Self::InvalidCipherKeyLength {
                nid,
                expected,
                actual,
            } => write!(
                f,
                "legacy UDP cipher NID {nid} has wrong key material length: expected {expected}, got {actual}"
            ),
            Self::CipherFailed { nid, message } => {
                write!(f, "legacy UDP cipher NID {nid} failed: {message}")
            }
            Self::DigestMismatch { nid, length } => {
                write!(
                    f,
                    "legacy UDP digest mismatch for NID {nid} with MAC length {length}"
                )
            }
            Self::DigestFailed { nid, message } => {
                write!(f, "legacy UDP digest NID {nid} failed: {message}")
            }
            Self::InvalidDigestLength {
                nid,
                requested,
                actual,
            } => write!(
                f,
                "legacy UDP digest NID {nid} has invalid MAC length: requested {requested}, actual {actual}"
            ),
            Self::UnsupportedDigest { nid, length } => write!(
                f,
                "unsupported legacy UDP digest NID {nid} with MAC length {length}"
            ),
            Self::InvalidCompression(compression) => {
                write!(f, "invalid legacy UDP compression {compression}")
            }
            Self::InvalidKeyMaterialLength { expected, actual } => write!(
                f,
                "legacy UDP key material has wrong length: expected {expected}, got {actual}"
            ),
            Self::Packet(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LegacyPacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DeviceError> for LegacyPacketError {
    fn from(error: DeviceError) -> Self {
        Self::Packet(error)
    }
}

impl From<LegacyPacketError> for TransportError {
    fn from(error: LegacyPacketError) -> Self {
        let message = error.to_string();
        let kind = match &error {
            LegacyPacketError::UnknownPeer(_) => io::ErrorKind::NotFound,
            LegacyPacketError::PacketTooShort { .. } => io::ErrorKind::UnexpectedEof,
            LegacyPacketError::Replayed { .. } | LegacyPacketError::FarFuture { .. } => {
                io::ErrorKind::InvalidData
            }
            LegacyPacketError::DigestMismatch { .. } => io::ErrorKind::InvalidData,
            LegacyPacketError::DigestFailed { .. } => io::ErrorKind::Other,
            LegacyPacketError::InvalidDigestLength { .. } => io::ErrorKind::InvalidInput,
            LegacyPacketError::UnsupportedCompression(_)
            | LegacyPacketError::UnsupportedCipher(_)
            | LegacyPacketError::UnsupportedDigest { .. } => io::ErrorKind::Unsupported,
            LegacyPacketError::InvalidCipherKeyLength { .. } => io::ErrorKind::InvalidInput,
            LegacyPacketError::InvalidCompression(_)
            | LegacyPacketError::InvalidKeyMaterialLength { .. } => io::ErrorKind::InvalidInput,
            LegacyPacketError::CipherFailed { .. } => io::ErrorKind::InvalidData,
            LegacyPacketError::CompressionFailed { .. } => io::ErrorKind::Other,
            LegacyPacketError::DecompressionFailed { .. } => io::ErrorKind::InvalidData,
            LegacyPacketError::Packet(_) => io::ErrorKind::InvalidData,
        };

        Self::Io(io::Error::new(kind, message))
    }
}

fn hmac_sha1(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).map_err(|error| LegacyPacketError::DigestFailed {
            nid: 64,
            message: error.to_string(),
        })?;
    mac.update(packet);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|error| LegacyPacketError::DigestFailed {
            nid: 672,
            message: error.to_string(),
        })?;
    mac.update(packet);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha384(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
    let mut mac =
        Hmac::<Sha384>::new_from_slice(key).map_err(|error| LegacyPacketError::DigestFailed {
            nid: 673,
            message: error.to_string(),
        })?;
    mac.update(packet);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).map_err(|error| LegacyPacketError::DigestFailed {
            nid: 674,
            message: error.to_string(),
        })?;
    mac.update(packet);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(feature = "openssl-legacy")]
fn openssl_cipher_nid_from_name(name: &str) -> Option<i32> {
    use std::ffi::CString;

    openssl::init();
    let name = CString::new(name).ok()?;
    let cipher = unsafe { openssl_sys::EVP_get_cipherbyname(name.as_ptr()) };
    if cipher.is_null() {
        None
    } else {
        let wrapped = unsafe { OpensslCipher::from_ptr(cipher) };
        Some(wrapped.nid().as_raw())
    }
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_cipher_nid_from_name(_name: &str) -> Option<i32> {
    None
}

#[cfg(feature = "openssl-legacy")]
fn openssl_cipher(nid: i32) -> Option<OpensslCipher> {
    let cipher = OpensslCipher::from_nid(Nid::from_raw(nid))?;
    if cipher.nid().as_raw() == 0 {
        None
    } else {
        Some(cipher)
    }
}

#[cfg(feature = "openssl-legacy")]
fn openssl_cipher_key_len(nid: i32) -> usize {
    openssl_cipher(nid).map_or(0, |cipher| cipher.key_len())
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_cipher_key_len(_nid: i32) -> usize {
    0
}

#[cfg(feature = "openssl-legacy")]
fn openssl_cipher_iv_len(nid: i32) -> usize {
    openssl_cipher(nid)
        .and_then(|cipher| cipher.iv_len())
        .unwrap_or(0)
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_cipher_iv_len(_nid: i32) -> usize {
    0
}

#[cfg(feature = "openssl-legacy")]
fn openssl_cipher_crypt(
    nid: i32,
    key_material: &[u8],
    packet: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, LegacyPacketError> {
    let cipher = openssl_cipher(nid).ok_or(LegacyPacketError::UnsupportedCipher(nid))?;
    let key_len = cipher.key_len();
    let iv_len = cipher.iv_len().unwrap_or(0);
    let expected = key_len + iv_len;

    if key_material.len() != expected {
        return Err(LegacyPacketError::InvalidCipherKeyLength {
            nid,
            expected,
            actual: key_material.len(),
        });
    }

    let (key, iv) = key_material.split_at(key_len);
    let iv = (iv_len != 0).then_some(iv);
    let mode = if encrypt {
        OpensslCipherMode::Encrypt
    } else {
        OpensslCipherMode::Decrypt
    };
    let mut crypter = openssl::symm::Crypter::new(cipher, mode, key, iv).map_err(|error| {
        LegacyPacketError::CipherFailed {
            nid,
            message: error.to_string(),
        }
    })?;
    let mut out = vec![0; packet.len() + cipher.block_size()];
    let count =
        crypter
            .update(packet, &mut out)
            .map_err(|error| LegacyPacketError::CipherFailed {
                nid,
                message: error.to_string(),
            })?;
    let rest =
        crypter
            .finalize(&mut out[count..])
            .map_err(|error| LegacyPacketError::CipherFailed {
                nid,
                message: error.to_string(),
            })?;
    out.truncate(count + rest);
    Ok(out)
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_cipher_crypt(
    nid: i32,
    _key_material: &[u8],
    _packet: &[u8],
    _encrypt: bool,
) -> Result<Vec<u8>, LegacyPacketError> {
    Err(LegacyPacketError::UnsupportedCipher(nid))
}

#[cfg(feature = "openssl-legacy")]
fn openssl_digest_nid_from_name(name: &str) -> Option<i32> {
    OpensslMessageDigest::from_name(name).map(|digest| digest.type_().as_raw())
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_digest_nid_from_name(_name: &str) -> Option<i32> {
    None
}

#[cfg(feature = "openssl-legacy")]
fn openssl_digest(nid: i32) -> Option<OpensslMessageDigest> {
    let digest = OpensslMessageDigest::from_nid(Nid::from_raw(nid))?;
    if digest.type_().as_raw() == 0 {
        None
    } else {
        Some(digest)
    }
}

#[cfg(feature = "openssl-legacy")]
fn openssl_digest_len(nid: i32) -> Option<usize> {
    openssl_digest(nid).map(|digest| digest.size())
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_digest_len(_nid: i32) -> Option<usize> {
    None
}

#[cfg(feature = "openssl-legacy")]
fn openssl_hmac(nid: i32, key: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    let digest = openssl_digest(nid)?;
    let key = PKey::hmac(key).ok()?;
    let mut signer = OpensslSigner::new(digest, &key).ok()?;
    signer.update(packet).ok()?;
    signer.sign_to_vec().ok()
}

#[cfg(not(feature = "openssl-legacy"))]
fn openssl_hmac(_nid: i32, _key: &[u8], _packet: &[u8]) -> Option<Vec<u8>> {
    None
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;

    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }

    diff == 0
}

const fn compression_is_unavailable(compression: CompressionLevel) -> bool {
    match compression {
        CompressionLevel::LzoLow | CompressionLevel::LzoHigh => !cfg!(feature = "lzo"),
        _ => false,
    }
}

pub const fn legacy_compression_is_available(compression: CompressionLevel) -> bool {
    !compression_is_unavailable(compression)
}

fn compress_zlib(
    packet: &[u8],
    compression: CompressionLevel,
    level: u32,
) -> Result<Vec<u8>, LegacyPacketError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), ZlibCompression::new(level));
    encoder
        .write_all(packet)
        .map_err(|error| LegacyPacketError::CompressionFailed {
            compression,
            message: error.to_string(),
        })?;
    encoder
        .finish()
        .map_err(|error| LegacyPacketError::CompressionFailed {
            compression,
            message: error.to_string(),
        })
}

fn uncompress_zlib(
    packet: &[u8],
    compression: CompressionLevel,
) -> Result<Vec<u8>, LegacyPacketError> {
    let decoder = ZlibDecoder::new(packet);
    let mut decoder = decoder.take((MTU + 1) as u64);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| LegacyPacketError::DecompressionFailed {
            compression,
            message: error.to_string(),
        })?;
    Ok(out)
}

fn uncompress_lz4(packet: &[u8]) -> Result<Vec<u8>, LegacyPacketError> {
    let mut out = vec![0; MTU + 1];
    let len = lz4_flex::block::decompress_into(packet, &mut out).map_err(|error| {
        LegacyPacketError::DecompressionFailed {
            compression: CompressionLevel::Lz4,
            message: error.to_string(),
        }
    })?;
    out.truncate(len);
    Ok(out)
}

#[cfg(feature = "lzo")]
fn compress_lzo(
    packet: &[u8],
    compression: CompressionLevel,
) -> Result<Vec<u8>, LegacyPacketError> {
    use lzo_sys::lzo1x::{LZO1X_1_MEM_COMPRESS, LZO1X_999_MEM_COMPRESS};
    use lzo_sys::lzoconf::LZO_E_OK;

    ensure_lzo_initialized(compression)?;

    let mut out = vec![0; packet.len() + packet.len() / 16 + 64 + 3];
    let mut out_len = out.len();
    let mut wrkmem = vec![0u8; LZO1X_1_MEM_COMPRESS.max(LZO1X_999_MEM_COMPRESS) as usize];
    let result = unsafe {
        match compression {
            CompressionLevel::LzoHigh => lzo_sys::lzo1x::lzo1x_999_compress(
                packet.as_ptr(),
                packet.len(),
                out.as_mut_ptr(),
                &mut out_len,
                wrkmem.as_mut_ptr().cast(),
            ),
            CompressionLevel::LzoLow => lzo_sys::lzo1x::lzo1x_1_compress(
                packet.as_ptr(),
                packet.len(),
                out.as_mut_ptr(),
                &mut out_len,
                wrkmem.as_mut_ptr().cast(),
            ),
            _ => unreachable!("compress_lzo only accepts LZO compression levels"),
        }
    };

    if result != LZO_E_OK {
        return Err(LegacyPacketError::CompressionFailed {
            compression,
            message: format!("lzo error {result}"),
        });
    }

    out.truncate(out_len);
    Ok(out)
}

#[cfg(not(feature = "lzo"))]
fn compress_lzo(
    _packet: &[u8],
    compression: CompressionLevel,
) -> Result<Vec<u8>, LegacyPacketError> {
    Err(LegacyPacketError::UnsupportedCompression(compression))
}

#[cfg(feature = "lzo")]
fn uncompress_lzo(
    packet: &[u8],
    compression: CompressionLevel,
) -> Result<Vec<u8>, LegacyPacketError> {
    use lzo_sys::lzoconf::LZO_E_OK;

    ensure_lzo_initialized(compression)?;

    let mut out = vec![0; MTU + 1];
    let mut out_len = out.len();
    let result = unsafe {
        lzo_sys::lzo1x::lzo1x_decompress_safe(
            packet.as_ptr(),
            packet.len(),
            out.as_mut_ptr(),
            &mut out_len,
            std::ptr::null_mut(),
        )
    };

    if result != LZO_E_OK {
        return Err(LegacyPacketError::DecompressionFailed {
            compression,
            message: format!("lzo error {result}"),
        });
    }

    out.truncate(out_len);
    Ok(out)
}

#[cfg(not(feature = "lzo"))]
fn uncompress_lzo(
    _packet: &[u8],
    compression: CompressionLevel,
) -> Result<Vec<u8>, LegacyPacketError> {
    Err(LegacyPacketError::UnsupportedCompression(compression))
}

#[cfg(feature = "lzo")]
fn ensure_lzo_initialized(compression: CompressionLevel) -> Result<(), LegacyPacketError> {
    use lzo_sys::lzoconf::LZO_E_OK;

    static LZO_INIT: OnceLock<i32> = OnceLock::new();
    let result = *LZO_INIT.get_or_init(|| unsafe { lzo_sys::lzoconf::lzo_init() });

    if result == LZO_E_OK {
        Ok(())
    } else {
        Err(LegacyPacketError::CompressionFailed {
            compression,
            message: format!("lzo_init error {result}"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyReplayWindow {
    window_bytes: usize,
    received_seqno: u32,
    received: u32,
    far_future: u32,
    late: Vec<u8>,
}

impl LegacyReplayWindow {
    pub fn new(window_bytes: usize) -> Self {
        Self {
            window_bytes,
            received_seqno: 0,
            received: 0,
            far_future: 0,
            late: vec![0; window_bytes],
        }
    }

    pub fn disabled() -> Self {
        Self::new(0)
    }

    pub fn reset(&mut self) {
        self.received_seqno = 0;
        self.received = 0;
        self.far_future = 0;
        self.late.fill(0);
    }

    pub const fn window_bytes(&self) -> usize {
        self.window_bytes
    }

    pub const fn received_seqno(&self) -> u32 {
        self.received_seqno
    }

    pub const fn received(&self) -> u32 {
        self.received
    }

    pub const fn far_future(&self) -> u32 {
        self.far_future
    }

    pub fn accept(&mut self, seqno: u32) -> Result<(), LegacyPacketError> {
        let window_bits = self.window_bytes.saturating_mul(8);

        if window_bits != 0 && seqno != self.received_seqno.wrapping_add(1) {
            let future_cutoff = self
                .received_seqno
                .saturating_add(u32::try_from(window_bits).unwrap_or(u32::MAX));

            if seqno >= future_cutoff {
                let count = self.far_future.saturating_add(1);
                self.far_future = count;

                if count <= u32::try_from(self.window_bytes >> 2).unwrap_or(u32::MAX) {
                    return Err(LegacyPacketError::FarFuture {
                        seqno,
                        received_seqno: self.received_seqno,
                        distance: seqno.saturating_sub(self.received_seqno).saturating_sub(1),
                        count,
                    });
                }

                self.late.fill(0);
            } else if seqno <= self.received_seqno {
                let outside_window = self.received_seqno >= window_bits as u32
                    && seqno <= self.received_seqno - window_bits as u32;

                if outside_window || !self.is_marked_late(seqno) {
                    return Err(LegacyPacketError::Replayed {
                        seqno,
                        received_seqno: self.received_seqno,
                    });
                }
            } else {
                for missed in self.received_seqno.saturating_add(1)..seqno {
                    self.mark_late(missed);
                }
            }

            self.far_future = 0;
            self.clear_late(seqno);
        } else if window_bits != 0 {
            self.far_future = 0;
            self.clear_late(seqno);
        }

        if seqno > self.received_seqno {
            self.received_seqno = seqno;
        }

        self.received = self.received.saturating_add(1);
        Ok(())
    }

    fn mark_late(&mut self, seqno: u32) {
        if self.window_bytes == 0 {
            return;
        }

        let index = (seqno as usize / 8) % self.window_bytes;
        self.late[index] |= 1 << (seqno % 8);
    }

    fn clear_late(&mut self, seqno: u32) {
        if self.window_bytes == 0 {
            return;
        }

        let index = (seqno as usize / 8) % self.window_bytes;
        self.late[index] &= !(1 << (seqno % 8));
    }

    fn is_marked_late(&self, seqno: u32) -> bool {
        if self.window_bytes == 0 {
            return false;
        }

        let index = (seqno as usize / 8) % self.window_bytes;
        self.late[index] & (1 << (seqno % 8)) != 0
    }
}

impl Default for LegacyReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyPeerState {
    pub incoming: LegacyPacketDirection,
    pub outgoing: LegacyPacketDirection,
    sent_seqno: u32,
    replay: LegacyReplayWindow,
}

impl LegacyPeerState {
    pub fn new(replay_window_bytes: usize) -> Self {
        Self {
            incoming: LegacyPacketDirection::default(),
            outgoing: LegacyPacketDirection::default(),
            sent_seqno: 0,
            replay: LegacyReplayWindow::new(replay_window_bytes),
        }
    }

    pub fn from_legacy_answer_key(
        message: &AnswerKeyMessage,
        replay_window_bytes: usize,
    ) -> Result<Self, LegacyPacketError> {
        let outgoing = LegacyPacketDirection::from_legacy_answer_key(message)?;
        Ok(Self::with_directions(
            LegacyPacketDirection::default(),
            outgoing,
            replay_window_bytes,
        ))
    }

    pub fn with_directions(
        incoming: LegacyPacketDirection,
        outgoing: LegacyPacketDirection,
        replay_window_bytes: usize,
    ) -> Self {
        Self {
            incoming,
            outgoing,
            sent_seqno: 0,
            replay: LegacyReplayWindow::new(replay_window_bytes),
        }
    }

    pub const fn sent_seqno(&self) -> u32 {
        self.sent_seqno
    }

    pub const fn replay(&self) -> &LegacyReplayWindow {
        &self.replay
    }

    pub fn clear_outgoing_key_state(&mut self) {
        self.outgoing = LegacyPacketDirection::default();
        self.reset_outgoing_key_state();
    }

    pub fn reset_incoming_key_state(&mut self) {
        self.replay.reset();
    }

    pub fn reset_outgoing_key_state(&mut self) {
        self.sent_seqno = 0;
    }

    pub fn apply_legacy_answer_key(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<(), LegacyPacketError> {
        self.outgoing = LegacyPacketDirection::from_legacy_answer_key(message)?;
        self.reset_outgoing_key_state();
        Ok(())
    }

    pub fn apply_incoming_legacy_answer_key(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<(), LegacyPacketError> {
        self.incoming = LegacyPacketDirection::from_legacy_answer_key(message)?;
        self.reset_incoming_key_state();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyUdpCodec {
    peers: BTreeMap<String, LegacyPeerState>,
    replay_window_bytes: usize,
}

impl LegacyUdpCodec {
    pub fn new(replay_window_bytes: usize) -> Self {
        Self {
            peers: BTreeMap::new(),
            replay_window_bytes,
        }
    }

    pub fn add_peer(&mut self, name: impl Into<String>) -> Option<LegacyPeerState> {
        self.insert_peer(name, LegacyPeerState::new(self.replay_window_bytes))
    }

    pub fn insert_peer(
        &mut self,
        name: impl Into<String>,
        peer: LegacyPeerState,
    ) -> Option<LegacyPeerState> {
        self.peers.insert(name.into(), peer)
    }

    pub fn peer(&self, name: &str) -> Option<&LegacyPeerState> {
        self.peers.get(name)
    }

    pub fn peer_mut(&mut self, name: &str) -> Option<&mut LegacyPeerState> {
        self.peers.get_mut(name)
    }

    pub fn remove_peer(&mut self, name: &str) -> Option<LegacyPeerState> {
        self.peers.remove(name)
    }

    pub fn clear_outgoing_key_state(&mut self, name: &str) {
        if let Some(peer) = self.peers.get_mut(name) {
            peer.clear_outgoing_key_state();
        }
    }

    pub const fn replay_window_bytes(&self) -> usize {
        self.replay_window_bytes
    }

    pub fn apply_incoming_legacy_answer_key(
        &mut self,
        peer: impl Into<String>,
        message: &AnswerKeyMessage,
    ) -> Result<(), LegacyPacketError> {
        let peer = peer.into();
        self.peers
            .entry(peer)
            .or_insert_with(|| LegacyPeerState::new(self.replay_window_bytes))
            .apply_incoming_legacy_answer_key(message)
    }

    pub fn verify_incoming_source(&self, datagram: &[u8]) -> Result<Option<&str>, TransportError> {
        let mut match_name = None;

        for (name, peer) in &self.peers {
            let minimum = LEGACY_SEQNO_LEN + peer.incoming.digest.length();
            if datagram.len() < minimum {
                continue;
            }

            if peer.incoming.digest.verify_active_packet(datagram).is_err() {
                continue;
            }

            if match_name.is_some() {
                return Ok(None);
            }

            match_name = Some(name.as_str());
        }

        Ok(match_name)
    }

    pub fn verifies_incoming_source_for(&self, peer: &str, datagram: &[u8]) -> bool {
        let Some(peer) = self.peers.get(peer) else {
            return false;
        };
        let minimum = LEGACY_SEQNO_LEN + peer.incoming.digest.length();
        if datagram.len() < minimum {
            return false;
        }

        peer.incoming.digest.verify_active_packet(datagram).is_ok()
    }
}

impl Default for LegacyUdpCodec {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_BYTES)
    }
}

impl PacketCodec for LegacyUdpCodec {
    fn encode(&mut self, target: &str, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        let Some(peer) = self.peers.get_mut(target) else {
            return Err(LegacyPacketError::UnknownPeer(target.to_owned()).into());
        };

        let compressed = peer.outgoing.compress(&packet.data)?;
        let seqno = peer.sent_seqno.wrapping_add(1);
        let mut framed = Vec::with_capacity(LEGACY_SEQNO_LEN + compressed.len());
        framed.extend_from_slice(&seqno.to_be_bytes());
        framed.extend_from_slice(&compressed);

        let encrypted = peer.outgoing.cipher.encrypt(&framed)?;
        let datagram = peer.outgoing.digest.append(&encrypted)?;
        peer.sent_seqno = seqno;

        Ok(datagram)
    }

    fn decode(&mut self, source: &str, datagram: &[u8]) -> Result<VpnPacket, TransportError> {
        let Some(peer) = self.peers.get_mut(source) else {
            return Err(LegacyPacketError::UnknownPeer(source.to_owned()).into());
        };

        let minimum = LEGACY_SEQNO_LEN + peer.incoming.digest.length();

        if datagram.len() < minimum {
            return Err(LegacyPacketError::PacketTooShort {
                minimum,
                actual: datagram.len(),
            }
            .into());
        }

        let authenticated = peer.incoming.digest.verify_and_strip(datagram)?;
        let decrypted = peer.incoming.cipher.decrypt(authenticated)?;

        if decrypted.len() < LEGACY_SEQNO_LEN {
            return Err(LegacyPacketError::PacketTooShort {
                minimum: LEGACY_SEQNO_LEN,
                actual: decrypted.len(),
            }
            .into());
        }

        let seqno = u32::from_be_bytes(
            decrypted[..LEGACY_SEQNO_LEN]
                .try_into()
                .expect("slice length checked"),
        );
        peer.replay.accept(seqno)?;

        if peer.replay.received_seqno() > MAX_LEGACY_SEQNO {
            peer.reset_incoming_key_state();
        }

        let payload = peer.incoming.uncompress(&decrypted[LEGACY_SEQNO_LEN..])?;
        VpnPacket::new(payload).map_err(|error| LegacyPacketError::from(error).into())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeIdTable {
    by_name: BTreeMap<String, NodeId>,
    by_id: BTreeMap<NodeId, String>,
}

impl NodeIdTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, id: NodeId) -> Option<NodeId> {
        let name = name.into();
        let previous = self.by_name.insert(name.clone(), id);

        if let Some(previous) = previous {
            self.by_id.remove(&previous);
        }

        if !id.is_null() {
            self.by_id.insert(id, name);
        }

        previous
    }

    pub fn id(&self, name: &str) -> Option<NodeId> {
        self.by_name.get(name).copied()
    }

    pub fn name(&self, id: NodeId) -> Option<&str> {
        self.by_id.get(&id).map(String::as_str)
    }

    pub fn from_network_state(state: &NetworkState) -> Self {
        let mut table = Self::new();

        for (name, id) in state.graph.node_ids() {
            table.insert(name, id);
        }

        table
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayEnvelope {
    pub destination: NodeId,
    pub source: NodeId,
    pub payload: Vec<u8>,
}

impl RelayEnvelope {
    pub fn direct(source: NodeId, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            destination: NodeId::NULL,
            source,
            payload: payload.into(),
        }
    }

    pub fn relayed(destination: NodeId, source: NodeId, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            destination,
            source,
            payload: payload.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RELAY_HEADER_LEN + self.payload.len());
        out.extend_from_slice(self.destination.as_bytes());
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(datagram: &[u8]) -> Result<Self, TransportError> {
        if datagram.len() < RELAY_HEADER_LEN {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "relay datagram too short: {} < {}",
                    datagram.len(),
                    RELAY_HEADER_LEN
                ),
            )));
        }

        let destination = NodeId::new(
            datagram[0..NODE_ID_LEN]
                .try_into()
                .expect("slice length checked by RELAY_HEADER_LEN"),
        );
        let source = NodeId::new(
            datagram[NODE_ID_LEN..RELAY_HEADER_LEN]
                .try_into()
                .expect("slice length checked by RELAY_HEADER_LEN"),
        );

        Ok(Self {
            destination,
            source,
            payload: datagram[RELAY_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsRelayCodec {
    ids: NodeIdTable,
    myself: NodeId,
}

impl SptpsRelayCodec {
    pub fn new(myself: NodeId, ids: NodeIdTable) -> Self {
        Self { ids, myself }
    }

    pub fn ids(&self) -> &NodeIdTable {
        &self.ids
    }

    pub fn ids_mut(&mut self) -> &mut NodeIdTable {
        &mut self.ids
    }

    pub fn encode_direct(&mut self, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        Ok(RelayEnvelope::direct(self.myself, packet.data.clone()).encode())
    }

    pub fn encode_relayed(
        &mut self,
        target: &str,
        packet: &VpnPacket,
    ) -> Result<Vec<u8>, TransportError> {
        let Some(target_id) = self.ids.id(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown target node ID for {target}"),
            )));
        };

        Ok(RelayEnvelope::relayed(target_id, self.myself, packet.data.clone()).encode())
    }
}

impl PacketCodec for SptpsRelayCodec {
    fn encode(&mut self, target: &str, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        self.encode_relayed(target, packet)
    }

    fn decode(&mut self, source: &str, datagram: &[u8]) -> Result<VpnPacket, TransportError> {
        let envelope = RelayEnvelope::decode(datagram)?;
        let Some(source_name) = self.ids.name(envelope.source) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown source node ID in relay datagram",
            )));
        };

        if source_name != source {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source address {source} does not match relay source ID {source_name}"),
            )));
        }

        if !envelope.destination.is_null() && envelope.destination != self.myself {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay datagram is not addressed to this node",
            )));
        }

        VpnPacket::new(envelope.payload).map_err(TransportError::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsPeerSession {
    state: SptpsPeerState,
    packet_type: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SptpsPeerState {
    Codec(SptpsDatagramCodec),
    Handshake(Box<SptpsHandshakeSession>),
}

impl SptpsPeerSession {
    pub fn new(codec: SptpsDatagramCodec, packet_type: u8) -> Result<Self, SptpsError> {
        if packet_type >= SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(packet_type));
        }

        Ok(Self {
            state: SptpsPeerState::Codec(codec),
            packet_type,
        })
    }

    pub fn from_handshake_session(
        session: SptpsHandshakeSession,
        packet_type: u8,
    ) -> Result<Self, SptpsError> {
        if packet_type >= SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(packet_type));
        }

        if !session.is_established() {
            return Err(SptpsError::MissingHandshakeState("established SPTPS keys"));
        }

        Ok(Self {
            state: SptpsPeerState::Handshake(Box::new(session)),
            packet_type,
        })
    }

    pub fn with_symmetric_key(
        key: SptpsKey,
        packet_type: u8,
        replay_window_bytes: usize,
    ) -> Result<Self, SptpsError> {
        Self::new(
            SptpsDatagramCodec::with_keys(key.clone(), key, replay_window_bytes),
            packet_type,
        )
    }

    pub fn codec(&self) -> &SptpsDatagramCodec {
        match &self.state {
            SptpsPeerState::Codec(codec) => codec,
            SptpsPeerState::Handshake(session) => session.codec(),
        }
    }

    pub fn codec_mut(&mut self) -> &mut SptpsDatagramCodec {
        match &mut self.state {
            SptpsPeerState::Codec(codec) => codec,
            SptpsPeerState::Handshake(session) => session.codec_mut(),
        }
    }

    pub const fn packet_type(&self) -> u8 {
        self.packet_type
    }

    pub fn verify_datagram(&self, datagram: &[u8]) -> Result<(), SptpsError> {
        match &self.state {
            SptpsPeerState::Codec(codec) => codec.verify_datagram(datagram),
            SptpsPeerState::Handshake(session) => session.verify_datagram(datagram),
        }
    }

    fn encode_record_with_type(
        &mut self,
        record_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SptpsError> {
        match &mut self.state {
            SptpsPeerState::Codec(codec) => codec.encode(record_type, payload),
            SptpsPeerState::Handshake(session) => session.send_record(record_type, payload),
        }
    }

    fn encode_packet(&mut self, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        let payload = sptps_payload_from_packet(self.packet_type, packet)?;
        self.encode_record_with_type(self.packet_type, &payload)
            .map_err(TransportError::from)
    }

    pub fn force_key_exchange(&mut self) -> Result<Vec<Vec<u8>>, SptpsError> {
        let SptpsPeerState::Handshake(session) = &mut self.state else {
            return Err(SptpsError::MissingHandshakeState(
                "established SPTPS handshake session",
            ));
        };

        session.force_kex()?;
        Ok(session.drain_outbound())
    }

    fn decode_record(&mut self, datagram: &[u8]) -> Result<SptpsRecord, SptpsError> {
        match &mut self.state {
            SptpsPeerState::Codec(codec) => codec.decode(datagram),
            SptpsPeerState::Handshake(session) => {
                let events = session.receive_datagram(datagram)?;

                match events.as_slice() {
                    [
                        SptpsHandshakeEvent::ApplicationRecord {
                            record_type,
                            payload,
                        },
                    ] => Ok(SptpsRecord::new(0, *record_type, payload.clone())),
                    [SptpsHandshakeEvent::HandshakeComplete] | [] => {
                        Err(SptpsError::InvalidRecordType(SPTPS_HANDSHAKE))
                    }
                    _ => Err(SptpsError::InvalidRecordType(SPTPS_HANDSHAKE)),
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsDecodedRecord {
    pub record_type: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsPacketCodec {
    ids: NodeIdTable,
    myself: NodeId,
    peers: BTreeMap<String, SptpsPeerSession>,
}

impl SptpsPacketCodec {
    pub fn new(myself: NodeId, ids: NodeIdTable) -> Self {
        Self {
            ids,
            myself,
            peers: BTreeMap::new(),
        }
    }

    pub fn ids(&self) -> &NodeIdTable {
        &self.ids
    }

    pub fn ids_mut(&mut self) -> &mut NodeIdTable {
        &mut self.ids
    }

    pub fn insert_peer(
        &mut self,
        name: impl Into<String>,
        session: SptpsPeerSession,
    ) -> Option<SptpsPeerSession> {
        self.peers.insert(name.into(), session)
    }

    pub fn peer(&self, name: &str) -> Option<&SptpsPeerSession> {
        self.peers.get(name)
    }

    pub fn peer_mut(&mut self, name: &str) -> Option<&mut SptpsPeerSession> {
        self.peers.get_mut(name)
    }

    pub fn peer_names(&self) -> impl Iterator<Item = &str> {
        self.peers.keys().map(String::as_str)
    }

    pub fn remove_peer(&mut self, name: &str) -> Option<SptpsPeerSession> {
        self.peers.remove(name)
    }

    pub fn encode_direct(
        &mut self,
        target: &str,
        packet: &VpnPacket,
    ) -> Result<Vec<u8>, TransportError> {
        let record = self.encode_record_for(target, packet)?;
        Ok(RelayEnvelope::direct(self.myself, record).encode())
    }

    pub fn encode_relayed(
        &mut self,
        target: &str,
        packet: &VpnPacket,
    ) -> Result<Vec<u8>, TransportError> {
        let Some(target_id) = self.ids.id(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown target node ID for {target}"),
            )));
        };
        let record = self.encode_record_for(target, packet)?;
        Ok(RelayEnvelope::relayed(target_id, self.myself, record).encode())
    }

    pub fn encode_direct_record(
        &mut self,
        target: &str,
        record_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let record = self.encode_record_payload_for(target, record_type, payload)?;
        Ok(RelayEnvelope::direct(self.myself, record).encode())
    }

    pub fn encode_relayed_record(
        &mut self,
        target: &str,
        record_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let Some(target_id) = self.ids.id(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown target node ID for {target}"),
            )));
        };
        let record = self.encode_record_payload_for(target, record_type, payload)?;
        Ok(RelayEnvelope::relayed(target_id, self.myself, record).encode())
    }

    fn encode_record_for(
        &mut self,
        target: &str,
        packet: &VpnPacket,
    ) -> Result<Vec<u8>, TransportError> {
        let Some(peer) = self.peers.get_mut(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing SPTPS session for {target}"),
            )));
        };

        peer.encode_packet(packet)
    }

    fn encode_record_payload_for(
        &mut self,
        target: &str,
        record_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let Some(peer) = self.peers.get_mut(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing SPTPS session for {target}"),
            )));
        };

        peer.encode_record_with_type(record_type, payload)
            .map_err(TransportError::from)
    }

    pub fn verify_direct_datagram_source(
        &self,
        datagram: &[u8],
    ) -> Result<Option<&str>, TransportError> {
        let envelope = RelayEnvelope::decode(datagram)?;

        if !envelope.destination.is_null() {
            return Ok(None);
        }

        let Some(source_name) = self.ids.name(envelope.source) else {
            return Ok(None);
        };
        let Some(peer) = self.peers.get(source_name) else {
            return Ok(None);
        };

        peer.verify_datagram(&envelope.payload)
            .map_err(TransportError::from)?;

        Ok(Some(source_name))
    }

    pub fn decode_record(
        &mut self,
        source: &str,
        datagram: &[u8],
    ) -> Result<SptpsDecodedRecord, TransportError> {
        let envelope = RelayEnvelope::decode(datagram)?;
        let Some(source_name) = self.ids.name(envelope.source) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown source node ID in SPTPS datagram",
            )));
        };

        if source_name != source {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source address {source} does not match SPTPS source ID {source_name}"),
            )));
        }

        if !envelope.destination.is_null() && envelope.destination != self.myself {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "SPTPS datagram is not addressed to this node",
            )));
        }

        let Some(peer) = self.peers.get_mut(source) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing SPTPS session for {source}"),
            )));
        };
        let record = peer.decode_record(&envelope.payload)?;

        Ok(SptpsDecodedRecord {
            record_type: record.record_type,
            payload: record.payload,
        })
    }
}

impl PacketCodec for SptpsPacketCodec {
    fn encode(&mut self, target: &str, packet: &VpnPacket) -> Result<Vec<u8>, TransportError> {
        self.encode_relayed(target, packet)
    }

    fn decode(&mut self, source: &str, datagram: &[u8]) -> Result<VpnPacket, TransportError> {
        let expected = self.peers.get(source).map(|peer| peer.packet_type);
        let Some(expected) = expected else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing SPTPS session for {source}"),
            )));
        };
        let record = self.decode_record(source, datagram)?;

        if record.record_type != expected {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected SPTPS record type {} from {source}, expected {}",
                    record.record_type, expected
                ),
            )));
        }

        sptps_packet_from_payload(record.record_type, record.payload)
    }
}

pub fn sptps_payload_from_packet(
    packet_type: u8,
    packet: &VpnPacket,
) -> Result<Vec<u8>, TransportError> {
    if sptps_packet_type_has_mac_header(packet_type) {
        return Ok(packet.data.clone());
    }
    if packet.data.len() < ETH_HLEN {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: ETH_HLEN,
            actual: packet.data.len(),
        }
        .into());
    }

    Ok(packet.data[ETH_HLEN..].to_vec())
}

pub fn sptps_packet_from_payload(
    packet_type: u8,
    payload: Vec<u8>,
) -> Result<VpnPacket, TransportError> {
    if sptps_packet_type_has_mac_header(packet_type) {
        return VpnPacket::new(payload).map_err(TransportError::from);
    }

    let Some(first) = payload.first() else {
        return Err(DeviceError::PacketTooShort {
            expected_at_least: 1,
            actual: 0,
        }
        .into());
    };
    let ether_type = match first >> 4 {
        4 => ETH_P_IP,
        6 => ETH_P_IPV6,
        version => return Err(DeviceError::UnknownIpVersion(version).into()),
    };

    let mut frame = Vec::with_capacity(ETH_HLEN + payload.len());
    frame.resize(ETH_HLEN - 2, 0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(&payload);
    VpnPacket::new(frame).map_err(TransportError::from)
}

fn sptps_packet_type_has_mac_header(packet_type: u8) -> bool {
    packet_type & SPTPS_PACKET_TYPE_MAC != 0
}

pub trait DatagramIo {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<usize>;
    fn recv_datagram(&mut self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>>;
}

impl DatagramIo for std::net::UdpSocket {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<usize> {
        self.send_to(payload, target)
    }

    fn recv_datagram(&mut self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.recv_from(buffer) {
            Ok((len, source)) => Ok(Some((len, source))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeAddressTable {
    by_name: BTreeMap<String, Vec<SocketAddr>>,
    by_addr: BTreeMap<SocketAddr, String>,
}

impl NodeAddressTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, address: SocketAddr) -> Option<SocketAddr> {
        let name = name.into();
        let previous = self.by_name.insert(name.clone(), vec![address]);

        if let Some(previous) = &previous {
            for address in previous {
                self.by_addr.remove(address);
            }
        }

        self.by_addr.insert(address, name);
        previous.and_then(|addresses| addresses.into_iter().next())
    }

    pub fn push(&mut self, name: impl Into<String>, address: SocketAddr) {
        let name = name.into();
        let addresses = self.by_name.entry(name.clone()).or_default();

        if addresses.contains(&address) {
            return;
        }

        addresses.push(address);
        self.by_addr.insert(address, name);
    }

    pub fn promote(&mut self, name: impl Into<String>, address: SocketAddr) {
        let name = name.into();
        let addresses = self.by_name.entry(name.clone()).or_default();

        if let Some(pos) = addresses.iter().position(|candidate| *candidate == address) {
            if pos > 0 {
                let address = addresses.remove(pos);
                addresses.insert(0, address);
            }
        } else {
            addresses.insert(0, address);
        }

        self.by_addr.insert(address, name);
    }

    pub fn address(&self, name: &str) -> Option<SocketAddr> {
        self.by_name
            .get(name)
            .and_then(|addresses| addresses.first().copied())
    }

    pub fn addresses(&self, name: &str) -> Option<&[SocketAddr]> {
        self.by_name.get(name).map(Vec::as_slice)
    }

    pub fn node(&self, address: &SocketAddr) -> Option<&str> {
        self.by_addr.get(address).map(String::as_str)
    }

    pub fn remove(&mut self, name: &str) -> Option<SocketAddr> {
        let addresses = self.by_name.remove(name)?;
        for address in &addresses {
            self.by_addr.remove(address);
        }
        addresses.into_iter().next()
    }
}

#[derive(Debug)]
pub enum DatagramTransportError {
    Transport(TransportError),
    UnknownTarget(String),
    UnknownSource(SocketAddr),
}

impl Clone for DatagramTransportError {
    fn clone(&self) -> Self {
        match self {
            Self::Transport(error) => Self::Transport(error.clone()),
            Self::UnknownTarget(target) => Self::UnknownTarget(target.clone()),
            Self::UnknownSource(source) => Self::UnknownSource(*source),
        }
    }
}

impl PartialEq for DatagramTransportError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Transport(left), Self::Transport(right)) => left == right,
            (Self::UnknownTarget(left), Self::UnknownTarget(right)) => left == right,
            (Self::UnknownSource(left), Self::UnknownSource(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for DatagramTransportError {}

impl fmt::Display for DatagramTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::UnknownTarget(target) => write!(f, "unknown target node {target}"),
            Self::UnknownSource(source) => write!(f, "unknown datagram source {source}"),
        }
    }
}

impl std::error::Error for DatagramTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::UnknownTarget(_) | Self::UnknownSource(_) => None,
        }
    }
}

impl From<TransportError> for DatagramTransportError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<DeviceError> for TransportError {
    fn from(error: DeviceError) -> Self {
        Self::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            error.to_string(),
        ))
    }
}

impl From<SptpsError> for TransportError {
    fn from(error: SptpsError) -> Self {
        let kind = match error {
            SptpsError::InvalidKeyLength { .. }
            | SptpsError::InvalidKeyMaterialLength { .. }
            | SptpsError::InvalidRecordType(_)
            | SptpsError::InvalidKexVersion(_)
            | SptpsError::InvalidPublicKeyLength { .. }
            | SptpsError::InvalidPrivateKeyLength { .. }
            | SptpsError::InvalidSignatureLength { .. }
            | SptpsError::InvalidPublicKeyBase64Length { .. }
            | SptpsError::InvalidPem { .. }
            | SptpsError::RecordTooLarge { .. } => io::ErrorKind::InvalidInput,
            SptpsError::PacketTooShort { .. } | SptpsError::InvalidKexLength { .. } => {
                io::ErrorKind::UnexpectedEof
            }
            SptpsError::UnexpectedSeqno { .. }
            | SptpsError::Replay { .. }
            | SptpsError::FarFuture { .. }
            | SptpsError::AuthenticationFailed
            | SptpsError::DuplicateKex
            | SptpsError::InvalidEd25519PublicKey
            | SptpsError::InvalidPemBase64(_)
            | SptpsError::SignatureVerificationFailed
            | SptpsError::MissingHandshakeState(_)
            | SptpsError::UnexpectedHandshakeRecord { .. }
            | SptpsError::InvalidRecordLength { .. } => io::ErrorKind::InvalidData,
            SptpsError::RandomFailed(_) => io::ErrorKind::Other,
        };

        Self::Io(io::Error::new(kind, error.to_string()))
    }
}

pub struct DatagramTransport<I, C> {
    io: I,
    codec: C,
    addresses: NodeAddressTable,
}

impl<I, C> DatagramTransport<I, C> {
    pub fn new(io: I, codec: C, addresses: NodeAddressTable) -> Self {
        Self {
            io,
            codec,
            addresses,
        }
    }

    pub fn addresses(&self) -> &NodeAddressTable {
        &self.addresses
    }

    pub fn addresses_mut(&mut self) -> &mut NodeAddressTable {
        &mut self.addresses
    }

    pub fn into_parts(self) -> (I, C, NodeAddressTable) {
        (self.io, self.codec, self.addresses)
    }
}

impl<I: DatagramIo, C: PacketCodec> DatagramTransport<I, C> {
    pub fn receive_packet(
        &mut self,
    ) -> Result<Option<(String, VpnPacket)>, DatagramTransportError> {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        let Some((len, source_addr)) = self
            .io
            .recv_datagram(&mut buffer)
            .map_err(|error| DatagramTransportError::Transport(TransportError::Io(error)))?
        else {
            return Ok(None);
        };

        let Some(source) = self.addresses.node(&source_addr).map(str::to_owned) else {
            return Err(DatagramTransportError::UnknownSource(source_addr));
        };

        buffer.truncate(len);
        let packet = self.codec.decode(&source, &buffer)?;
        Ok(Some((source, packet)))
    }
}

impl<I: DatagramIo, C: PacketCodec> PacketTransport for DatagramTransport<I, C> {
    fn send_packet(&mut self, target: &str, packet: &VpnPacket) -> Result<(), TransportError> {
        let Some(address) = self.addresses.address(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown target node {target}"),
            )));
        };

        let payload = self.codec.encode(target, packet)?;
        let sent = self.io.send_datagram(address, &payload)?;

        if sent != payload.len() {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short datagram send: {sent} < {}", payload.len()),
            )));
        }

        Ok(())
    }
}

impl<I: DatagramIo, C: PacketCodec> PacketReceiver for DatagramTransport<I, C> {
    fn receive_packet(&mut self) -> Result<Option<(String, VpnPacket)>, TransportError> {
        DatagramTransport::receive_packet(self).map_err(|error| match error {
            DatagramTransportError::Transport(error) => error,
            DatagramTransportError::UnknownTarget(target) => TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown target node {target}"),
            )),
            DatagramTransportError::UnknownSource(source) => TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown datagram source {source}"),
            )),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryDatagramIo {
    incoming: VecDeque<(SocketAddr, Vec<u8>)>,
    outgoing: Vec<(SocketAddr, Vec<u8>)>,
}

impl MemoryDatagramIo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_incoming(&mut self, source: SocketAddr, payload: impl Into<Vec<u8>>) {
        self.incoming.push_back((source, payload.into()));
    }

    pub fn outgoing(&self) -> &[(SocketAddr, Vec<u8>)] {
        &self.outgoing
    }
}

impl DatagramIo for MemoryDatagramIo {
    fn send_datagram(&mut self, target: SocketAddr, payload: &[u8]) -> io::Result<usize> {
        self.outgoing.push((target, payload.to_vec()));
        Ok(payload.len())
    }

    fn recv_datagram(&mut self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        let Some((source, payload)) = self.incoming.pop_front() else {
            return Ok(None);
        };

        if payload.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("datagram too large: {} > {}", payload.len(), buffer.len()),
            ));
        }

        buffer[..payload.len()].copy_from_slice(&payload);
        Ok(Some((payload.len(), source)))
    }
}

#[cfg(test)]
mod tests {
    use tinc_core::protocol::parse_meta_message;
    use tinc_core::state::NetworkState;
    use tinc_core::utils::bin_to_hex;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn packet() -> VpnPacket {
        VpnPacket::new(vec![1, 2, 3, 4]).unwrap()
    }

    fn ethernet_ipv4_packet(destination: [u8; 4]) -> VpnPacket {
        let mut payload = vec![0; 20];
        payload[0] = 0x45;
        payload[2..4].copy_from_slice(&20u16.to_be_bytes());
        payload[8] = 64;
        payload[9] = 17;
        payload[12..16].copy_from_slice(&[192, 0, 2, 1]);
        payload[16..20].copy_from_slice(&destination);

        let mut frame = vec![0; ETH_HLEN - 2];
        frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
        frame.extend_from_slice(&payload);
        VpnPacket::new(frame).unwrap()
    }

    fn node_id(byte: u8) -> NodeId {
        NodeId::new([byte; NODE_ID_LEN])
    }

    fn legacy_datagram(seqno: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = seqno.to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn node_address_table_maps_names_and_addresses() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeAddressTable::new();
        assert_eq!(None, table.insert("alpha", addr(1)));
        assert_eq!(Some(addr(1)), table.address("alpha"));
        assert_eq!(Some("alpha"), table.node(&addr(1)));

        table.push("alpha", addr(3));
        assert_eq!(Some(&[addr(1), addr(3)][..]), table.addresses("alpha"));
        assert_eq!(Some("alpha"), table.node(&addr(3)));

        assert_eq!(Some(addr(1)), table.insert("alpha", addr(2)));
        assert_eq!(None, table.node(&addr(1)));
        assert_eq!(None, table.node(&addr(3)));
        assert_eq!(Some("alpha"), table.node(&addr(2)));

        assert_eq!(Some(addr(2)), table.remove("alpha"));
        assert_eq!(None, table.address("alpha"));
    }

    #[test]
    fn node_id_table_can_be_built_from_core_network_state() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(
                parse_meta_message("12 1 myself alpha 203.0.113.1 655 0 1").unwrap(),
            )
            .unwrap();

        let table = NodeIdTable::from_network_state(&state);

        assert_eq!(Some(NodeId::from_name("myself")), table.id("myself"));
        assert_eq!(Some(NodeId::from_name("alpha")), table.id("alpha"));
        assert_eq!(Some("alpha"), table.name(NodeId::from_name("alpha")));
    }

    #[test]
    fn plain_codec_roundtrips_packet_bytes() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = PlainPacketCodec;
        let packet = packet();
        let encoded = codec.encode("alpha", &packet).unwrap();
        assert_eq!(packet.data, encoded);
        assert_eq!(packet, codec.decode("alpha", &encoded).unwrap());
    }

    #[test]
    fn compression_level_values_match_tinc_constants() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(Ok(CompressionLevel::None), CompressionLevel::try_from(0));
        assert_eq!(Ok(CompressionLevel::Zlib1), CompressionLevel::try_from(1));
        assert_eq!(Ok(CompressionLevel::Zlib9), CompressionLevel::try_from(9));
        assert_eq!(Ok(CompressionLevel::LzoLow), CompressionLevel::try_from(10));
        assert_eq!(
            Ok(CompressionLevel::LzoHigh),
            CompressionLevel::try_from(11)
        );
        assert_eq!(Ok(CompressionLevel::Lz4), CompressionLevel::try_from(12));
        assert_eq!(Err(13), CompressionLevel::try_from(13));
    }

    #[test]
    fn legacy_digest_nids_and_mac_lengths_match_tinc() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(LegacyDigest::None, LegacyDigest::from_nid_and_length(0, 4));

        let sha1 = LegacyDigest::from_nid_and_length(64, usize::MAX);
        assert_eq!(64, sha1.nid());
        assert_eq!(20, sha1.length());

        let sha256 = LegacyDigest::from_nid_and_length(672, 99);
        assert_eq!(672, sha256.nid());
        assert_eq!(32, sha256.length());

        let sha384_zero = LegacyDigest::from_nid_and_length(673, 0);
        assert_eq!(673, sha384_zero.nid());
        assert_eq!(0, sha384_zero.length());

        let unknown = LegacyDigest::from_nid_and_length(9999, 7);
        assert_eq!(9999, unknown.nid());
        assert_eq!(7, unknown.length());
    }

    #[test]
    fn legacy_cipher_nids_and_key_lengths_match_openssl() {
        tinc_test_support::assert_can_create_netns();
        let aes128 = LegacyCipherAlgorithm::from_nid(419);
        assert_eq!(LegacyCipherAlgorithm::Aes128Cbc, aes128);
        assert_eq!(32, aes128.key_material_len());

        let aes192 = LegacyCipherAlgorithm::from_nid(423);
        assert_eq!(LegacyCipherAlgorithm::Aes192Cbc, aes192);
        assert_eq!(40, aes192.key_material_len());

        let aes256 = LegacyCipherAlgorithm::from_nid(427);
        assert_eq!(LegacyCipherAlgorithm::Aes256Cbc, aes256);
        assert_eq!(48, aes256.key_material_len());

        assert_eq!(
            LegacyCipherAlgorithm::None,
            LegacyCipherAlgorithm::from_nid(0)
        );
        assert_eq!(
            LegacyCipherAlgorithm::Unsupported(9999),
            LegacyCipherAlgorithm::from_nid(9999)
        );
    }

    #[test]
    fn legacy_codec_prepends_big_endian_sequence_numbers() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = LegacyUdpCodec::default();
        codec.add_peer("alpha");

        assert_eq!(
            vec![0, 0, 0, 1, 1, 2, 3, 4],
            codec.encode("alpha", &packet()).unwrap()
        );
        assert_eq!(
            vec![0, 0, 0, 2, 1, 2, 3, 4],
            codec.encode("alpha", &packet()).unwrap()
        );
        assert_eq!(2, codec.peer("alpha").unwrap().sent_seqno());
    }

    #[test]
    fn legacy_codec_decodes_out_of_order_packets_and_rejects_replays() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = LegacyUdpCodec::default();
        codec.add_peer("alpha");

        assert_eq!(
            VpnPacket::new(vec![1]).unwrap(),
            codec.decode("alpha", &legacy_datagram(1, &[1])).unwrap()
        );
        assert!(matches!(
            codec.decode("alpha", &legacy_datagram(1, &[1])),
            Err(TransportError::Io(_))
        ));

        assert_eq!(
            VpnPacket::new(vec![3]).unwrap(),
            codec.decode("alpha", &legacy_datagram(3, &[3])).unwrap()
        );
        assert_eq!(
            VpnPacket::new(vec![2]).unwrap(),
            codec.decode("alpha", &legacy_datagram(2, &[2])).unwrap()
        );
        assert!(matches!(
            codec.decode("alpha", &legacy_datagram(2, &[2])),
            Err(TransportError::Io(_))
        ));

        let replay = codec.peer("alpha").unwrap().replay();
        assert_eq!(3, replay.received_seqno());
        assert_eq!(3, replay.received());
    }

    #[test]
    fn legacy_codec_roundtrips_supported_compressed_packets() {
        tinc_test_support::assert_can_create_netns();
        let compressions = [
            CompressionLevel::Zlib1,
            CompressionLevel::Zlib9,
            CompressionLevel::Lz4,
            #[cfg(feature = "lzo")]
            CompressionLevel::LzoLow,
            #[cfg(feature = "lzo")]
            CompressionLevel::LzoHigh,
        ];

        for compression in compressions {
            let mut codec = LegacyUdpCodec::default();
            let direction = LegacyPacketDirection::new(
                compression,
                LegacyCipher::none(),
                LegacyDigestState::default(),
            );
            codec.insert_peer(
                "alpha",
                LegacyPeerState::with_directions(
                    direction.clone(),
                    direction,
                    DEFAULT_REPLAY_WINDOW_BYTES,
                ),
            );
            let packet = VpnPacket::new(vec![42; 256]).unwrap();

            let encoded = codec.encode("alpha", &packet).unwrap();

            assert_eq!(&1u32.to_be_bytes(), &encoded[..LEGACY_SEQNO_LEN]);
            assert!(encoded.len() < LEGACY_SEQNO_LEN + packet.len());
            assert_eq!(packet, codec.decode("alpha", &encoded).unwrap());
        }
    }

    #[test]
    fn legacy_replay_window_handles_far_future_packets_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut replay = LegacyReplayWindow::new(4);
        replay.accept(1).unwrap();

        assert!(matches!(
            replay.accept(40),
            Err(LegacyPacketError::FarFuture {
                seqno: 40,
                received_seqno: 1,
                distance: 38,
                count: 1,
            })
        ));
        assert_eq!(1, replay.received_seqno());

        replay.accept(40).unwrap();
        assert_eq!(40, replay.received_seqno());
        assert_eq!(2, replay.received());
    }

    #[test]
    fn legacy_codec_appends_and_verifies_truncated_hmac_sha256() {
        tinc_test_support::assert_can_create_netns();
        let digest = LegacyDigest::from_nid_and_length(672, 4).with_key(b"packet-key");
        let mut codec = LegacyUdpCodec::default();
        let direction =
            LegacyPacketDirection::new(CompressionLevel::None, LegacyCipher::none(), digest);
        codec.insert_peer(
            "alpha",
            LegacyPeerState::with_directions(
                direction.clone(),
                direction,
                DEFAULT_REPLAY_WINDOW_BYTES,
            ),
        );

        let encoded = codec.encode("alpha", &packet()).unwrap();

        assert_eq!(vec![0, 0, 0, 1, 1, 2, 3, 4, 67, 44, 101, 212], encoded);
        assert_eq!(packet(), codec.decode("alpha", &encoded).unwrap());

        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            codec.decode("alpha", &tampered),
            Err(TransportError::Io(_))
        ));
    }

    #[test]
    fn legacy_codec_identifies_source_by_active_digest_without_consuming_replay_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let digest = LegacyDigest::from_nid_and_length(672, 4).with_key(b"packet-key");
        let mut codec = LegacyUdpCodec::default();
        let direction =
            LegacyPacketDirection::new(CompressionLevel::None, LegacyCipher::none(), digest);
        codec.insert_peer(
            "alpha",
            LegacyPeerState::with_directions(
                direction.clone(),
                direction,
                DEFAULT_REPLAY_WINDOW_BYTES,
            ),
        );

        let encoded = codec.encode("alpha", &packet()).unwrap();

        assert_eq!(
            Some("alpha"),
            codec.verify_incoming_source(&encoded).unwrap()
        );
        assert_eq!(0, codec.peer("alpha").unwrap().replay().received_seqno());
        assert_eq!(packet(), codec.decode("alpha", &encoded).unwrap());
        assert_eq!(1, codec.peer("alpha").unwrap().replay().received_seqno());

        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(None, codec.verify_incoming_source(&tampered).unwrap());
    }

    #[test]
    fn legacy_codec_roundtrips_aes_256_cbc_with_truncated_hmac() {
        tinc_test_support::assert_can_create_netns();
        let key_material: Vec<u8> = (0..48).collect();
        let cipher = LegacyCipher::from_nid_key(427, key_material.clone());
        assert_eq!(LegacyCipherAlgorithm::Aes256Cbc, cipher.algorithm());
        assert_eq!(48, cipher.key_material_len());

        let digest = LegacyDigest::from_nid_and_length(672, 4).with_key(key_material.clone());
        let direction = LegacyPacketDirection::new(CompressionLevel::None, cipher, digest);
        let mut codec = LegacyUdpCodec::default();
        codec.insert_peer(
            "alpha",
            LegacyPeerState::with_directions(
                direction.clone(),
                direction,
                DEFAULT_REPLAY_WINDOW_BYTES,
            ),
        );
        let packet = VpnPacket::new(b"legacy encrypted payload".to_vec()).unwrap();

        let encoded = codec.encode("alpha", &packet).unwrap();

        assert_ne!(legacy_datagram(1, &packet.data), encoded);
        assert_eq!(4, encoded.len() % AES_BLOCK_LEN);
        assert_eq!(packet, codec.decode("alpha", &encoded).unwrap());

        let mut tampered = encoded;
        tampered[0] ^= 1;
        assert!(matches!(
            codec.decode("alpha", &tampered),
            Err(TransportError::Io(_))
        ));
    }

    #[cfg(feature = "openssl-legacy")]
    #[test]
    fn legacy_codec_roundtrips_openssl_cipher_and_digest_by_nid_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let cipher_algorithm = LegacyCipherAlgorithm::from_name("DES-EDE3-CBC").unwrap();
        let digest_algorithm = LegacyDigest::from_name_and_length("MD5", 4).unwrap();
        assert!(matches!(
            cipher_algorithm,
            LegacyCipherAlgorithm::Unsupported(_)
        ));
        assert!(matches!(digest_algorithm, LegacyDigest::Unsupported { .. }));

        let key_material: Vec<u8> = (0..cipher_algorithm.key_material_len())
            .map(|value| value as u8)
            .collect();
        let cipher = LegacyCipher::new(cipher_algorithm, key_material.clone());
        let digest = digest_algorithm.with_key(key_material);
        let direction = LegacyPacketDirection::new(CompressionLevel::None, cipher, digest);
        let mut codec = LegacyUdpCodec::default();
        codec.insert_peer(
            "alpha",
            LegacyPeerState::with_directions(
                direction.clone(),
                direction,
                DEFAULT_REPLAY_WINDOW_BYTES,
            ),
        );
        let packet = VpnPacket::new(b"openssl legacy cipher and digest".to_vec()).unwrap();

        let encoded = codec.encode("alpha", &packet).unwrap();

        assert_ne!(legacy_datagram(1, &packet.data), encoded);
        assert_eq!(packet, codec.decode("alpha", &encoded).unwrap());
    }

    #[test]
    fn legacy_cipher_roundtrips_all_supported_aes_cbc_sizes() {
        tinc_test_support::assert_can_create_netns();
        for (nid, key_material_len) in [(419, 32), (423, 40), (427, 48)] {
            let key_material: Vec<u8> = (0..key_material_len).map(|value| value as u8).collect();
            let cipher = LegacyCipher::from_nid_key(nid, key_material);
            let payload = legacy_datagram(1, b"abc");

            let encrypted = cipher.encrypt(&payload).unwrap();

            assert_ne!(payload, encrypted);
            assert_eq!(0, encrypted.len() % AES_BLOCK_LEN);
            assert_eq!(payload, cipher.decrypt(&encrypted).unwrap());
        }
    }

    #[test]
    fn legacy_cipher_rejects_wrong_key_length_and_bad_padding() {
        tinc_test_support::assert_can_create_netns();
        let cipher = LegacyCipher::from_nid_key(427, vec![0; 47]);
        assert!(matches!(
            cipher.encrypt(b"abc"),
            Err(LegacyPacketError::InvalidCipherKeyLength {
                nid: 427,
                expected: 48,
                actual: 47,
            })
        ));

        let cipher = LegacyCipher::from_nid_key(427, vec![0; 48]);
        assert!(matches!(
            cipher.decrypt(&[0; AES_BLOCK_LEN]),
            Err(LegacyPacketError::CipherFailed { nid: 427, .. })
        ));
    }

    #[test]
    fn legacy_peer_state_can_be_built_from_answer_key_message() {
        tinc_test_support::assert_can_create_netns();
        let key_material: Vec<u8> = (0..48).collect();
        let message = match parse_meta_message(&format!(
            "16 alpha myself {} 427 672 4 0",
            bin_to_hex(&key_material)
        ))
        .unwrap()
        {
            tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
            _ => panic!("expected ANS_KEY"),
        };

        let mut peer =
            LegacyPeerState::from_legacy_answer_key(&message, DEFAULT_REPLAY_WINDOW_BYTES).unwrap();

        assert_eq!(
            LegacyCipherAlgorithm::Aes256Cbc,
            peer.outgoing.cipher.algorithm()
        );
        assert_eq!(
            LegacyDigest::Sha256 { length: 4 },
            peer.outgoing.digest.algorithm()
        );
        assert_eq!(CompressionLevel::None, peer.outgoing.compression);

        peer.incoming = peer.outgoing.clone();
        let mut codec = LegacyUdpCodec::default();
        codec.insert_peer("alpha", peer);

        let packet = VpnPacket::new(b"from answer key".to_vec()).unwrap();
        let encoded = codec.encode("alpha", &packet).unwrap();

        assert_eq!(packet, codec.decode("alpha", &encoded).unwrap());
    }

    #[test]
    fn legacy_peer_state_can_install_generated_answer_key_as_incoming_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let key_material: Vec<u8> = (0..48).rev().collect();
        let message = match parse_meta_message(&format!(
            "16 myself alpha {} 427 672 4 0",
            bin_to_hex(&key_material)
        ))
        .unwrap()
        {
            tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
            _ => panic!("expected ANS_KEY"),
        };

        let mut sender = LegacyUdpCodec::default();
        sender
            .apply_incoming_legacy_answer_key("alpha", &message)
            .unwrap();
        let mut receiver = LegacyUdpCodec::default();
        receiver.insert_peer(
            "myself",
            LegacyPeerState::from_legacy_answer_key(&message, DEFAULT_REPLAY_WINDOW_BYTES).unwrap(),
        );

        assert_eq!(
            LegacyCipherAlgorithm::Aes256Cbc,
            sender.peer("alpha").unwrap().incoming.cipher.algorithm()
        );
        assert_eq!(
            LegacyDigest::Sha256 { length: 4 },
            sender.peer("alpha").unwrap().incoming.digest.algorithm()
        );

        let packet = VpnPacket::new(b"using generated inbound key".to_vec()).unwrap();
        let encoded = receiver.encode("myself", &packet).unwrap();

        assert_eq!(packet, sender.decode("alpha", &encoded).unwrap());
    }

    #[test]
    fn legacy_peer_state_rejects_invalid_answer_key_parameters() {
        tinc_test_support::assert_can_create_netns();
        let key_material: Vec<u8> = (0..48).collect();
        let key = bin_to_hex(&key_material);

        let invalid_compression =
            match parse_meta_message(&format!("16 alpha myself {key} 427 672 4 13")).unwrap() {
                tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
                _ => panic!("expected ANS_KEY"),
            };
        assert!(matches!(
            LegacyPeerState::from_legacy_answer_key(
                &invalid_compression,
                DEFAULT_REPLAY_WINDOW_BYTES
            ),
            Err(LegacyPacketError::InvalidCompression(13))
        ));

        let lzo_compression =
            match parse_meta_message(&format!("16 alpha myself {key} 427 672 4 10")).unwrap() {
                tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
                _ => panic!("expected ANS_KEY"),
            };
        #[cfg(feature = "lzo")]
        assert_eq!(
            CompressionLevel::LzoLow,
            LegacyPeerState::from_legacy_answer_key(&lzo_compression, DEFAULT_REPLAY_WINDOW_BYTES)
                .unwrap()
                .outgoing
                .compression
        );
        #[cfg(not(feature = "lzo"))]
        assert!(matches!(
            LegacyPeerState::from_legacy_answer_key(&lzo_compression, DEFAULT_REPLAY_WINDOW_BYTES),
            Err(LegacyPacketError::UnsupportedCompression(
                CompressionLevel::LzoLow
            ))
        ));

        let invalid_mac =
            match parse_meta_message(&format!("16 alpha myself {key} 427 672 99 0")).unwrap() {
                tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
                _ => panic!("expected ANS_KEY"),
            };
        assert!(matches!(
            LegacyPeerState::from_legacy_answer_key(&invalid_mac, DEFAULT_REPLAY_WINDOW_BYTES),
            Err(LegacyPacketError::InvalidDigestLength {
                nid: 672,
                requested: 99,
                actual: 32,
            })
        ));

        let short_key = bin_to_hex(&key_material[..47]);
        let invalid_key = match parse_meta_message(&format!(
            "16 alpha myself {short_key} 427 672 4 0"
        ))
        .unwrap()
        {
            tinc_core::protocol::MetaMessage::AnswerKey(message) => message,
            _ => panic!("expected ANS_KEY"),
        };
        assert!(matches!(
            LegacyPeerState::from_legacy_answer_key(&invalid_key, DEFAULT_REPLAY_WINDOW_BYTES),
            Err(LegacyPacketError::InvalidKeyMaterialLength {
                expected: 48,
                actual: 47,
            })
        ));
    }

    #[test]
    fn disabled_legacy_replay_window_allows_duplicate_sequence_numbers() {
        tinc_test_support::assert_can_create_netns();
        let mut replay = LegacyReplayWindow::disabled();

        replay.accept(1).unwrap();
        replay.accept(1).unwrap();

        assert_eq!(1, replay.received_seqno());
        assert_eq!(2, replay.received());
    }

    #[test]
    fn legacy_codec_rejects_unknown_short_and_unsupported_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = LegacyUdpCodec::default();
        assert!(matches!(
            codec.encode("alpha", &packet()),
            Err(TransportError::Io(_))
        ));

        codec.add_peer("alpha");
        assert!(matches!(
            codec.decode("alpha", &[0, 0, 0]),
            Err(TransportError::Io(_))
        ));

        let outgoing = LegacyPacketDirection::new(
            CompressionLevel::None,
            LegacyCipher::new(LegacyCipherAlgorithm::Unsupported(9999), Vec::new()),
            LegacyDigestState::default(),
        );
        codec.insert_peer(
            "beta",
            LegacyPeerState::with_directions(
                LegacyPacketDirection::default(),
                outgoing,
                DEFAULT_REPLAY_WINDOW_BYTES,
            ),
        );

        let error = codec.encode("beta", &packet()).unwrap_err();
        let TransportError::Io(error) = error;
        assert_eq!(io::ErrorKind::Unsupported, error.kind());
        assert_eq!(0, codec.peer("beta").unwrap().sent_seqno());
    }

    #[test]
    fn sptps_packet_codec_encrypts_records_inside_relay_envelope() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([7; crate::sptps::SPTPS_KEY_LEN]);
        assert!(
            sender
                .insert_peer(
                    "alpha",
                    SptpsPeerSession::with_symmetric_key(key.clone(), 2, 16).unwrap(),
                )
                .is_none()
        );
        assert!(
            receiver
                .insert_peer(
                    "myself",
                    SptpsPeerSession::with_symmetric_key(key, 2, 16).unwrap(),
                )
                .is_none()
        );
        let packet = packet();

        let encoded = sender.encode("alpha", &packet).unwrap();

        assert_eq!(&[1; NODE_ID_LEN], &encoded[..NODE_ID_LEN]);
        assert_eq!(&[9; NODE_ID_LEN], &encoded[NODE_ID_LEN..RELAY_HEADER_LEN]);
        assert_ne!(&packet.data, &encoded[RELAY_HEADER_LEN..]);
        assert_eq!(packet, receiver.decode("myself", &encoded).unwrap());
        assert_eq!(1, sender.peer("alpha").unwrap().codec().out_seqno());
        assert_eq!(
            1,
            receiver
                .peer("myself")
                .unwrap()
                .codec()
                .in_replay()
                .expected_seqno()
        );
    }

    #[test]
    fn sptps_packet_codec_can_encode_direct_envelope_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([11; crate::sptps::SPTPS_KEY_LEN]);
        sender.insert_peer(
            "alpha",
            SptpsPeerSession::with_symmetric_key(key.clone(), 2, 16).unwrap(),
        );
        receiver.insert_peer(
            "myself",
            SptpsPeerSession::with_symmetric_key(key, 2, 16).unwrap(),
        );
        let packet = packet();

        let encoded = sender.encode_direct("alpha", &packet).unwrap();

        assert_eq!(&[0; NODE_ID_LEN], &encoded[..NODE_ID_LEN]);
        assert_eq!(&[9; NODE_ID_LEN], &encoded[NODE_ID_LEN..RELAY_HEADER_LEN]);
        assert_eq!(packet, receiver.decode("myself", &encoded).unwrap());
    }

    #[test]
    fn sptps_packet_codec_strips_router_ethernet_header_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([13; crate::sptps::SPTPS_KEY_LEN]);
        sender.insert_peer(
            "alpha",
            SptpsPeerSession::with_symmetric_key(key.clone(), 0, 16).unwrap(),
        );
        receiver.insert_peer(
            "myself",
            SptpsPeerSession::with_symmetric_key(key, 0, 16).unwrap(),
        );
        let packet = ethernet_ipv4_packet([10, 0, 0, 42]);

        let encoded = sender.encode_direct("alpha", &packet).unwrap();
        let record = receiver.decode_record("myself", &encoded).unwrap();

        assert_eq!(0, record.record_type);
        assert_eq!(&packet.data[ETH_HLEN..], record.payload.as_slice());

        let encoded = sender.encode_direct("alpha", &packet).unwrap();
        assert_eq!(packet, receiver.decode("myself", &encoded).unwrap());
    }

    #[test]
    fn sptps_packet_codec_keeps_mac_header_for_switch_mode_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([14; crate::sptps::SPTPS_KEY_LEN]);
        sender.insert_peer(
            "alpha",
            SptpsPeerSession::with_symmetric_key(key.clone(), SPTPS_PACKET_TYPE_MAC, 16).unwrap(),
        );
        receiver.insert_peer(
            "myself",
            SptpsPeerSession::with_symmetric_key(key, SPTPS_PACKET_TYPE_MAC, 16).unwrap(),
        );
        let packet = ethernet_ipv4_packet([10, 0, 0, 43]);

        let encoded = sender.encode_direct("alpha", &packet).unwrap();
        let record = receiver.decode_record("myself", &encoded).unwrap();

        assert_eq!(SPTPS_PACKET_TYPE_MAC, record.record_type);
        assert_eq!(packet.data, record.payload);

        let encoded = sender.encode_direct("alpha", &packet).unwrap();
        assert_eq!(packet, receiver.decode("myself", &encoded).unwrap());
    }

    #[test]
    fn sptps_packet_codec_can_encode_and_decode_probe_records_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([12; crate::sptps::SPTPS_KEY_LEN]);
        sender.insert_peer(
            "alpha",
            SptpsPeerSession::with_symmetric_key(key.clone(), 2, 16).unwrap(),
        );
        receiver.insert_peer(
            "myself",
            SptpsPeerSession::with_symmetric_key(key, 2, 16).unwrap(),
        );

        let encoded = sender.encode_direct_record("alpha", 4, b"probe").unwrap();
        let record = receiver.decode_record("myself", &encoded).unwrap();

        assert_eq!(4, record.record_type);
        assert_eq!(b"probe", record.payload.as_slice());
    }

    #[test]
    fn sptps_packet_codec_verifies_direct_source_without_consuming_replay_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids);

        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);

        let key = SptpsKey::new([12; crate::sptps::SPTPS_KEY_LEN]);
        sender.insert_peer(
            "alpha",
            SptpsPeerSession::with_symmetric_key(key.clone(), 2, 16).unwrap(),
        );
        receiver.insert_peer(
            "myself",
            SptpsPeerSession::with_symmetric_key(key, 2, 16).unwrap(),
        );

        let encoded = sender.encode_direct_record("alpha", 4, b"probe").unwrap();

        assert_eq!(
            Some("myself"),
            receiver.verify_direct_datagram_source(&encoded).unwrap()
        );
        assert_eq!(
            0,
            receiver
                .peer("myself")
                .unwrap()
                .codec()
                .in_replay()
                .expected_seqno()
        );

        let record = receiver.decode_record("myself", &encoded).unwrap();
        assert_eq!(4, record.record_type);
        assert_eq!(b"probe", record.payload.as_slice());
        assert_eq!(
            1,
            receiver
                .peer("myself")
                .unwrap()
                .codec()
                .in_replay()
                .expected_seqno()
        );
        let error = receiver
            .verify_direct_datagram_source(&encoded)
            .unwrap_err();
        let TransportError::Io(error) = error;
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[test]
    fn sptps_packet_codec_rejects_missing_sessions_and_wrong_record_type() {
        tinc_test_support::assert_can_create_netns();
        let mut ids = NodeIdTable::new();
        ids.insert("myself", node_id(9));
        ids.insert("alpha", node_id(1));
        let mut sender = SptpsPacketCodec::new(node_id(9), ids.clone());
        let mut receiver = SptpsPacketCodec::new(node_id(1), ids);
        let key = SptpsKey::new([8; crate::sptps::SPTPS_KEY_LEN]);

        let error = sender.encode("alpha", &packet()).unwrap_err();
        let TransportError::Io(error) = error;
        assert_eq!(io::ErrorKind::NotFound, error.kind());

        assert!(
            sender
                .insert_peer(
                    "alpha",
                    SptpsPeerSession::with_symmetric_key(key.clone(), 3, 16).unwrap(),
                )
                .is_none()
        );
        assert!(
            receiver
                .insert_peer(
                    "myself",
                    SptpsPeerSession::with_symmetric_key(key, 2, 16).unwrap(),
                )
                .is_none()
        );

        let encoded = sender.encode("alpha", &packet()).unwrap();
        let error = receiver.decode("myself", &encoded).unwrap_err();
        let TransportError::Io(error) = error;
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[test]
    fn relay_envelope_encodes_destination_then_source_id() {
        tinc_test_support::assert_can_create_netns();
        let envelope = RelayEnvelope::relayed(node_id(1), node_id(2), [9, 8, 7]);
        let encoded = envelope.encode();

        assert_eq!(&[1; NODE_ID_LEN], &encoded[..NODE_ID_LEN]);
        assert_eq!(&[2; NODE_ID_LEN], &encoded[NODE_ID_LEN..RELAY_HEADER_LEN]);
        assert_eq!(&[9, 8, 7], &encoded[RELAY_HEADER_LEN..]);
        assert_eq!(envelope, RelayEnvelope::decode(&encoded).unwrap());
    }

    #[test]
    fn relay_envelope_rejects_short_datagrams() {
        tinc_test_support::assert_can_create_netns();
        assert!(matches!(
            RelayEnvelope::decode(&[0; RELAY_HEADER_LEN - 1]),
            Err(TransportError::Io(_))
        ));
    }

    #[test]
    fn sptps_relay_codec_adds_node_id_prefix_on_encode() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeIdTable::new();
        table.insert("myself", node_id(9));
        table.insert("alpha", node_id(1));
        let mut codec = SptpsRelayCodec::new(node_id(9), table);
        let packet = packet();

        let encoded = codec.encode("alpha", &packet).unwrap();

        assert_eq!(&[1; NODE_ID_LEN], &encoded[..NODE_ID_LEN]);
        assert_eq!(&[9; NODE_ID_LEN], &encoded[NODE_ID_LEN..RELAY_HEADER_LEN]);
        assert_eq!(&packet.data, &encoded[RELAY_HEADER_LEN..]);
    }

    #[test]
    fn sptps_relay_codec_decodes_direct_and_relayed_packets_for_myself() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeIdTable::new();
        table.insert("myself", node_id(9));
        table.insert("alpha", node_id(1));
        let mut codec = SptpsRelayCodec::new(node_id(9), table);

        let direct = RelayEnvelope::direct(node_id(1), [1, 2, 3]).encode();
        assert_eq!(
            VpnPacket::new(vec![1, 2, 3]).unwrap(),
            codec.decode("alpha", &direct).unwrap()
        );

        let relayed = RelayEnvelope::relayed(node_id(9), node_id(1), [4, 5, 6]).encode();
        assert_eq!(
            VpnPacket::new(vec![4, 5, 6]).unwrap(),
            codec.decode("alpha", &relayed).unwrap()
        );
    }

    #[test]
    fn sptps_relay_codec_rejects_unknown_or_mismatched_ids() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeIdTable::new();
        table.insert("myself", node_id(9));
        table.insert("alpha", node_id(1));
        let mut codec = SptpsRelayCodec::new(node_id(9), table);

        let unknown_source = RelayEnvelope::direct(node_id(2), [1, 2, 3]).encode();
        assert!(matches!(
            codec.decode("alpha", &unknown_source),
            Err(TransportError::Io(_))
        ));

        let mismatched_source = RelayEnvelope::direct(node_id(1), [1, 2, 3]).encode();
        assert!(matches!(
            codec.decode("beta", &mismatched_source),
            Err(TransportError::Io(_))
        ));

        let wrong_destination = RelayEnvelope::relayed(node_id(8), node_id(1), [1, 2, 3]).encode();
        assert!(matches!(
            codec.decode("alpha", &wrong_destination),
            Err(TransportError::Io(_))
        ));
    }

    #[test]
    fn datagram_transport_sends_encoded_packets_to_known_node() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeAddressTable::new();
        table.insert("alpha", addr(1234));
        let io = MemoryDatagramIo::new();
        let mut transport = DatagramTransport::new(io, PlainPacketCodec, table);

        transport.send_packet("alpha", &packet()).unwrap();

        let (io, _, _) = transport.into_parts();
        assert_eq!(&[(addr(1234), vec![1, 2, 3, 4])], io.outgoing());
    }

    #[test]
    fn datagram_transport_reports_unknown_send_target() {
        tinc_test_support::assert_can_create_netns();
        let io = MemoryDatagramIo::new();
        let mut transport = DatagramTransport::new(io, PlainPacketCodec, NodeAddressTable::new());

        let error = transport.send_packet("alpha", &packet()).unwrap_err();
        assert!(matches!(error, TransportError::Io(_)));
    }

    #[test]
    fn datagram_transport_receives_packet_from_known_source() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeAddressTable::new();
        table.insert("alpha", addr(1234));
        let mut io = MemoryDatagramIo::new();
        io.push_incoming(addr(1234), vec![9, 8, 7]);
        let mut transport = DatagramTransport::new(io, PlainPacketCodec, table);

        assert_eq!(
            Some(("alpha".to_owned(), VpnPacket::new(vec![9, 8, 7]).unwrap())),
            transport.receive_packet().unwrap()
        );
        assert_eq!(None, transport.receive_packet().unwrap());
    }

    #[test]
    fn datagram_transport_rejects_unknown_source() {
        tinc_test_support::assert_can_create_netns();
        let mut io = MemoryDatagramIo::new();
        io.push_incoming(addr(1234), vec![9, 8, 7]);
        let mut transport = DatagramTransport::new(io, PlainPacketCodec, NodeAddressTable::new());

        assert_eq!(
            Err(DatagramTransportError::UnknownSource(addr(1234))),
            transport.receive_packet()
        );
    }

    #[test]
    fn datagram_transport_propagates_decode_errors() {
        tinc_test_support::assert_can_create_netns();
        let mut table = NodeAddressTable::new();
        table.insert("alpha", addr(1234));
        let mut io = MemoryDatagramIo::new();
        io.push_incoming(addr(1234), vec![0; MTU + 1]);
        let mut transport = DatagramTransport::new(io, PlainPacketCodec, table);

        assert!(matches!(
            transport.receive_packet(),
            Err(DatagramTransportError::Transport(TransportError::Io(_)))
        ));
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::VecDeque;
use std::fmt;

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use poly1305::universal_hash::KeyInit;
use poly1305::{Key as Poly1305Key, Poly1305};
use sha2::{Digest, Sha512};
use tinc_core::utils::{Base64DecodeError, b64decode_tinc, b64encode_tinc};

pub const SPTPS_VERSION: u8 = 0;
pub const SPTPS_HANDSHAKE: u8 = 128;
pub const SPTPS_ALERT: u8 = 129;
pub const SPTPS_CLOSE: u8 = 130;
pub const SPTPS_DATAGRAM_OVERHEAD: usize = 21;
pub const SPTPS_SEQNO_LEN: usize = 4;
pub const SPTPS_TAG_LEN: usize = 16;
pub const SPTPS_TCP_HEADER_LEN: usize = 3;
pub const SPTPS_TCP_AUTH_OVERHEAD: usize = 19;
pub const SPTPS_KEY_LEN: usize = 64;
pub const SPTPS_KEY_MATERIAL_LEN: usize = SPTPS_KEY_LEN * 2;
pub const SPTPS_KEX_NONCE_LEN: usize = 32;
pub const SPTPS_KEX_PUBKEY_LEN: usize = 32;
pub const SPTPS_KEX_LEN: usize = 1 + SPTPS_KEX_NONCE_LEN + SPTPS_KEX_PUBKEY_LEN;
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_EXPANDED_PRIVATE_KEY_LEN: usize = 64;
pub const ED25519_TINC_PRIVATE_KEY_LEN: usize =
    ED25519_EXPANDED_PRIVATE_KEY_LEN + ED25519_PUBLIC_KEY_LEN;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_BASE64_LEN: usize = 43;
pub const DEFAULT_SPTPS_REPLAY_WINDOW_BYTES: usize = 16;
const SPTPS_PRF_DIGEST_LEN: usize = 64;
const ED25519_PUBLIC_PEM_TYPE: &str = "ED25519 PUBLIC KEY";
const ED25519_PRIVATE_PEM_TYPE: &str = "ED25519 PRIVATE KEY";
const TINC_PEM_CHUNK_LEN: usize = 48;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsKey([u8; SPTPS_KEY_LEN]);

impl SptpsKey {
    pub fn new(bytes: [u8; SPTPS_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SptpsError> {
        let key = bytes.try_into().map_err(|_| SptpsError::InvalidKeyLength {
            expected: SPTPS_KEY_LEN,
            actual: bytes.len(),
        })?;

        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; SPTPS_KEY_LEN] {
        &self.0
    }

    fn chacha_key(&self) -> &[u8; 32] {
        self.0[..32]
            .try_into()
            .expect("SPTPS key contains a 32-byte ChaCha key")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsKeyMaterial {
    pub key0: SptpsKey,
    pub key1: SptpsKey,
}

impl SptpsKeyMaterial {
    pub fn new(bytes: [u8; SPTPS_KEY_MATERIAL_LEN]) -> Self {
        let key0 = bytes[..SPTPS_KEY_LEN]
            .try_into()
            .expect("first half is an SPTPS key");
        let key1 = bytes[SPTPS_KEY_LEN..]
            .try_into()
            .expect("second half is an SPTPS key");

        Self {
            key0: SptpsKey::new(key0),
            key1: SptpsKey::new(key1),
        }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SptpsError> {
        let material = bytes
            .try_into()
            .map_err(|_| SptpsError::InvalidKeyMaterialLength {
                expected: SPTPS_KEY_MATERIAL_LEN,
                actual: bytes.len(),
            })?;

        Ok(Self::new(material))
    }

    pub fn derive(
        shared_secret: &[u8],
        initiator_nonce: &[u8; SPTPS_KEX_NONCE_LEN],
        responder_nonce: &[u8; SPTPS_KEX_NONCE_LEN],
        label: &[u8],
    ) -> Self {
        let mut seed =
            Vec::with_capacity(b"key expansion".len() + SPTPS_KEX_NONCE_LEN * 2 + label.len());
        seed.extend_from_slice(b"key expansion");
        seed.extend_from_slice(initiator_nonce);
        seed.extend_from_slice(responder_nonce);
        seed.extend_from_slice(label);

        let mut material = [0; SPTPS_KEY_MATERIAL_LEN];
        sptps_prf(shared_secret, &seed, &mut material);
        Self::new(material)
    }

    pub fn as_bytes(&self) -> [u8; SPTPS_KEY_MATERIAL_LEN] {
        let mut out = [0; SPTPS_KEY_MATERIAL_LEN];
        out[..SPTPS_KEY_LEN].copy_from_slice(self.key0.as_bytes());
        out[SPTPS_KEY_LEN..].copy_from_slice(self.key1.as_bytes());
        out
    }

    pub fn keys_for_role(&self, initiator: bool) -> (SptpsKey, SptpsKey) {
        if initiator {
            (self.key0.clone(), self.key1.clone())
        } else {
            (self.key1.clone(), self.key0.clone())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsRecord {
    pub seqno: u32,
    pub record_type: u8,
    pub payload: Vec<u8>,
}

impl SptpsRecord {
    pub fn new(seqno: u32, record_type: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            seqno,
            record_type,
            payload: payload.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SptpsHandshakeState {
    Kex = 1,
    SecondaryKex = 2,
    Sig = 3,
    Ack = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SptpsError {
    InvalidKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidKeyMaterialLength {
        expected: usize,
        actual: usize,
    },
    InvalidRecordType(u8),
    InvalidKexLength {
        expected: usize,
        actual: usize,
    },
    InvalidKexVersion(u8),
    DuplicateKex,
    InvalidPublicKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidPrivateKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidSignatureLength {
        expected: usize,
        actual: usize,
    },
    InvalidPublicKeyBase64Length {
        expected: usize,
        actual: usize,
    },
    InvalidPem {
        pem_type: &'static str,
    },
    InvalidPemBase64(Base64DecodeError),
    InvalidEd25519PublicKey,
    SignatureVerificationFailed,
    RandomFailed(String),
    MissingHandshakeState(&'static str),
    UnexpectedHandshakeRecord {
        state: SptpsHandshakeState,
        len: usize,
    },
    PacketTooShort {
        minimum: usize,
        actual: usize,
    },
    RecordTooLarge {
        maximum: usize,
        actual: usize,
    },
    InvalidRecordLength {
        expected: usize,
        actual: usize,
    },
    UnexpectedSeqno {
        expected: u32,
        actual: u32,
    },
    Replay {
        seqno: u32,
        expected_seqno: u32,
    },
    FarFuture {
        seqno: u32,
        expected_seqno: u32,
        distance: u32,
        count: u32,
    },
    AuthenticationFailed,
}

impl fmt::Display for SptpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid SPTPS key length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidKeyMaterialLength { expected, actual } => {
                write!(
                    f,
                    "invalid SPTPS key material length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidRecordType(record_type) => {
                write!(f, "invalid SPTPS record type {record_type}")
            }
            Self::InvalidKexLength { expected, actual } => {
                write!(
                    f,
                    "invalid SPTPS KEX length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidKexVersion(version) => {
                write!(f, "invalid SPTPS KEX version {version}")
            }
            Self::DuplicateKex => write!(f, "duplicate SPTPS KEX before previous KEX completed"),
            Self::InvalidPublicKeyLength { expected, actual } => write!(
                f,
                "invalid Ed25519 public key length: expected {expected}, got {actual}"
            ),
            Self::InvalidPrivateKeyLength { expected, actual } => write!(
                f,
                "invalid Ed25519 private key length: expected {expected}, got {actual}"
            ),
            Self::InvalidSignatureLength { expected, actual } => write!(
                f,
                "invalid Ed25519 signature length: expected {expected}, got {actual}"
            ),
            Self::InvalidPublicKeyBase64Length { expected, actual } => write!(
                f,
                "invalid Ed25519 public key base64 length: expected {expected}, got {actual}"
            ),
            Self::InvalidPem { pem_type } => write!(f, "invalid {pem_type} PEM data"),
            Self::InvalidPemBase64(error) => write!(f, "{error}"),
            Self::InvalidEd25519PublicKey => write!(f, "invalid Ed25519 public key"),
            Self::SignatureVerificationFailed => write!(f, "SPTPS signature verification failed"),
            Self::RandomFailed(message) => write!(f, "SPTPS random generation failed: {message}"),
            Self::MissingHandshakeState(field) => {
                write!(f, "missing SPTPS handshake state: {field}")
            }
            Self::UnexpectedHandshakeRecord { state, len } => {
                write!(
                    f,
                    "unexpected SPTPS handshake record in state {state:?} with {len} bytes"
                )
            }
            Self::PacketTooShort { minimum, actual } => {
                write!(
                    f,
                    "SPTPS datagram too short: expected at least {minimum}, got {actual}"
                )
            }
            Self::RecordTooLarge { maximum, actual } => {
                write!(f, "SPTPS record too large: maximum {maximum}, got {actual}")
            }
            Self::InvalidRecordLength { expected, actual } => {
                write!(
                    f,
                    "invalid SPTPS record length: expected {expected}, got {actual}"
                )
            }
            Self::UnexpectedSeqno { expected, actual } => {
                write!(
                    f,
                    "unexpected SPTPS packet seqno: expected {expected}, got {actual}"
                )
            }
            Self::Replay {
                seqno,
                expected_seqno,
            } => write!(
                f,
                "late or replayed SPTPS packet seqno {seqno}, expected {expected_seqno}"
            ),
            Self::FarFuture {
                seqno,
                expected_seqno,
                distance,
                count,
            } => write!(
                f,
                "SPTPS packet seqno {seqno} is {distance} seqs in the future from {expected_seqno} ({count})"
            ),
            Self::AuthenticationFailed => write!(f, "SPTPS datagram authentication failed"),
        }
    }
}

impl std::error::Error for SptpsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPemBase64(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TincEd25519PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl TincEd25519PublicKey {
    pub fn new(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SptpsError> {
        let public_key = bytes
            .try_into()
            .map_err(|_| SptpsError::InvalidPublicKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            })?;

        Ok(Self(public_key))
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn from_base64(input: &str) -> Result<Self, SptpsError> {
        if input.len() != ED25519_PUBLIC_KEY_BASE64_LEN {
            return Err(SptpsError::InvalidPublicKeyBase64Length {
                expected: ED25519_PUBLIC_KEY_BASE64_LEN,
                actual: input.len(),
            });
        }

        let public_key = b64decode_tinc(input).map_err(SptpsError::InvalidPemBase64)?;
        Self::try_from_slice(&public_key)
    }

    pub fn to_base64(self) -> String {
        b64encode_tinc(&self.0)
    }

    pub fn from_pem(input: &str) -> Result<Self, SptpsError> {
        let data = read_tinc_pem(input, ED25519_PUBLIC_PEM_TYPE, ED25519_PUBLIC_KEY_LEN)?;
        Self::try_from_slice(&data)
    }

    pub fn to_pem(self) -> String {
        write_tinc_pem(ED25519_PUBLIC_PEM_TYPE, &self.0)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SptpsError> {
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(SptpsError::InvalidSignatureLength {
                expected: ED25519_SIGNATURE_LEN,
                actual: signature.len(),
            });
        }

        if signature[ED25519_SIGNATURE_LEN - 1] & 0xe0 != 0 {
            return Err(SptpsError::SignatureVerificationFailed);
        }

        let public_point = self.edwards_point()?;
        let r_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = signature[..ED25519_PUBLIC_KEY_LEN]
            .try_into()
            .expect("signature R length checked");
        let s_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = signature[ED25519_PUBLIC_KEY_LEN..]
            .try_into()
            .expect("signature S length checked");
        let h = ed25519_hram(&r_bytes, &self.0, message);
        let s = Scalar::from_bytes_mod_order(s_bytes);
        let neg_public = -public_point;
        let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &neg_public, &s);

        if constant_time_eq(&check.compress().to_bytes(), &r_bytes) {
            Ok(())
        } else {
            Err(SptpsError::SignatureVerificationFailed)
        }
    }

    fn edwards_point(&self) -> Result<EdwardsPoint, SptpsError> {
        CompressedEdwardsY(self.0)
            .decompress()
            .ok_or(SptpsError::InvalidEd25519PublicKey)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TincEd25519PrivateKey {
    expanded_private_key: [u8; ED25519_EXPANDED_PRIVATE_KEY_LEN],
    public_key: TincEd25519PublicKey,
}

impl TincEd25519PrivateKey {
    pub fn from_seed(seed: [u8; ED25519_SEED_LEN]) -> Self {
        let mut expanded_private_key = sha512_digest(&seed);
        clamp_ed25519_scalar(&mut expanded_private_key[..ED25519_PUBLIC_KEY_LEN]);
        let scalar: [u8; ED25519_PUBLIC_KEY_LEN] = expanded_private_key[..ED25519_PUBLIC_KEY_LEN]
            .try_into()
            .expect("expanded private key has a 32-byte scalar");
        let public_key =
            TincEd25519PublicKey::new(EdwardsPoint::mul_base_clamped(scalar).compress().to_bytes());

        Self {
            expanded_private_key,
            public_key,
        }
    }

    pub fn from_expanded_private_and_public(
        expanded_private_key: [u8; ED25519_EXPANDED_PRIVATE_KEY_LEN],
        public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            expanded_private_key,
            public_key: TincEd25519PublicKey::new(public_key),
        }
    }

    pub fn try_from_tinc_private_key(bytes: &[u8]) -> Result<Self, SptpsError> {
        if bytes.len() != ED25519_TINC_PRIVATE_KEY_LEN {
            return Err(SptpsError::InvalidPrivateKeyLength {
                expected: ED25519_TINC_PRIVATE_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let expanded_private_key = bytes[..ED25519_EXPANDED_PRIVATE_KEY_LEN]
            .try_into()
            .expect("private key length checked");
        let public_key = bytes[ED25519_EXPANDED_PRIVATE_KEY_LEN..]
            .try_into()
            .expect("public key length checked");

        Ok(Self::from_expanded_private_and_public(
            expanded_private_key,
            public_key,
        ))
    }

    pub fn public_key(&self) -> TincEd25519PublicKey {
        self.public_key
    }

    pub fn expanded_private_key(&self) -> &[u8; ED25519_EXPANDED_PRIVATE_KEY_LEN] {
        &self.expanded_private_key
    }

    pub fn as_tinc_private_key(&self) -> [u8; ED25519_TINC_PRIVATE_KEY_LEN] {
        let mut out = [0; ED25519_TINC_PRIVATE_KEY_LEN];
        out[..ED25519_EXPANDED_PRIVATE_KEY_LEN].copy_from_slice(&self.expanded_private_key);
        out[ED25519_EXPANDED_PRIVATE_KEY_LEN..].copy_from_slice(self.public_key.as_bytes());
        out
    }

    pub fn from_pem(input: &str) -> Result<Self, SptpsError> {
        let data = read_tinc_pem(
            input,
            ED25519_PRIVATE_PEM_TYPE,
            ED25519_TINC_PRIVATE_KEY_LEN,
        )?;
        Self::try_from_tinc_private_key(&data)
    }

    pub fn to_pem(&self) -> String {
        write_tinc_pem(ED25519_PRIVATE_PEM_TYPE, &self.as_tinc_private_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        let mut r_hasher = Sha512::new();
        r_hasher.update(&self.expanded_private_key[ED25519_PUBLIC_KEY_LEN..]);
        r_hasher.update(message);
        let r = Scalar::from_bytes_mod_order_wide(&digest_to_array(r_hasher.finalize()));
        let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let h = ed25519_hram(&r_bytes, self.public_key.as_bytes(), message);
        let private_scalar: [u8; ED25519_PUBLIC_KEY_LEN] = self.expanded_private_key
            [..ED25519_PUBLIC_KEY_LEN]
            .try_into()
            .expect("expanded private key has a 32-byte scalar");
        let private_scalar = Scalar::from_bytes_mod_order(private_scalar);
        let s = (h * private_scalar + r).to_bytes();

        let mut signature = [0; ED25519_SIGNATURE_LEN];
        signature[..ED25519_PUBLIC_KEY_LEN].copy_from_slice(&r_bytes);
        signature[ED25519_PUBLIC_KEY_LEN..].copy_from_slice(&s);
        signature
    }
}

impl fmt::Debug for TincEd25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TincEd25519PrivateKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SptpsEphemeralKey {
    expanded_private_key: [u8; ED25519_EXPANDED_PRIVATE_KEY_LEN],
    public_key: [u8; SPTPS_KEX_PUBKEY_LEN],
}

impl SptpsEphemeralKey {
    pub fn generate() -> Result<Self, SptpsError> {
        Ok(Self::from_seed(random_array()?))
    }

    pub fn from_seed(seed: [u8; ED25519_SEED_LEN]) -> Self {
        let key = TincEd25519PrivateKey::from_seed(seed);
        Self {
            expanded_private_key: *key.expanded_private_key(),
            public_key: *key.public_key().as_bytes(),
        }
    }

    pub fn public_key(&self) -> &[u8; SPTPS_KEX_PUBKEY_LEN] {
        &self.public_key
    }

    pub fn compute_shared(
        &self,
        peer_public_key: &[u8; SPTPS_KEX_PUBKEY_LEN],
    ) -> Result<[u8; SPTPS_KEX_PUBKEY_LEN], SptpsError> {
        let peer = CompressedEdwardsY(*peer_public_key)
            .decompress()
            .ok_or(SptpsError::InvalidEd25519PublicKey)?
            .to_montgomery();
        let scalar: [u8; ED25519_PUBLIC_KEY_LEN] = self.expanded_private_key
            [..ED25519_PUBLIC_KEY_LEN]
            .try_into()
            .expect("expanded private key has a 32-byte scalar");

        Ok(peer.mul_clamped(scalar).0)
    }
}

impl fmt::Debug for SptpsEphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SptpsEphemeralKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SptpsKex {
    pub version: u8,
    pub nonce: [u8; SPTPS_KEX_NONCE_LEN],
    pub public_key: [u8; SPTPS_KEX_PUBKEY_LEN],
}

impl SptpsKex {
    pub fn new(nonce: [u8; SPTPS_KEX_NONCE_LEN], public_key: [u8; SPTPS_KEX_PUBKEY_LEN]) -> Self {
        Self {
            version: SPTPS_VERSION,
            nonce,
            public_key,
        }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SptpsError> {
        if bytes.len() != SPTPS_KEX_LEN {
            return Err(SptpsError::InvalidKexLength {
                expected: SPTPS_KEX_LEN,
                actual: bytes.len(),
            });
        }

        if bytes[0] != SPTPS_VERSION {
            return Err(SptpsError::InvalidKexVersion(bytes[0]));
        }

        let nonce = bytes[1..1 + SPTPS_KEX_NONCE_LEN]
            .try_into()
            .expect("KEX length checked");
        let public_key = bytes[1 + SPTPS_KEX_NONCE_LEN..]
            .try_into()
            .expect("KEX length checked");

        Ok(Self::new(nonce, public_key))
    }

    pub fn to_bytes(self) -> [u8; SPTPS_KEX_LEN] {
        let mut out = [0; SPTPS_KEX_LEN];
        out[0] = self.version;
        out[1..1 + SPTPS_KEX_NONCE_LEN].copy_from_slice(&self.nonce);
        out[1 + SPTPS_KEX_NONCE_LEN..].copy_from_slice(&self.public_key);
        out
    }
}

pub fn sptps_signature_message(
    initiator: bool,
    kex0: &SptpsKex,
    kex1: &SptpsKex,
    label: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + SPTPS_KEX_LEN * 2 + label.len());
    message.push(u8::from(initiator));
    message.extend_from_slice(&kex0.to_bytes());
    message.extend_from_slice(&kex1.to_bytes());
    message.extend_from_slice(label);
    message
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsReplayWindow {
    window_bytes: usize,
    expected_seqno: u32,
    received: u32,
    far_future: u32,
    late: Vec<u8>,
}

impl SptpsReplayWindow {
    pub fn new(window_bytes: usize) -> Self {
        Self {
            window_bytes,
            expected_seqno: 0,
            received: 0,
            far_future: 0,
            late: vec![0; window_bytes],
        }
    }

    pub fn disabled() -> Self {
        Self::new(0)
    }

    pub const fn window_bytes(&self) -> usize {
        self.window_bytes
    }

    pub const fn expected_seqno(&self) -> u32 {
        self.expected_seqno
    }

    pub const fn received(&self) -> u32 {
        self.received
    }

    pub const fn far_future(&self) -> u32 {
        self.far_future
    }

    pub fn accept(&mut self, seqno: u32) -> Result<(), SptpsError> {
        self.check(seqno, true)
    }

    pub fn verify(&self, seqno: u32) -> Result<(), SptpsError> {
        let mut probe = self.clone();
        probe.check(seqno, false)
    }

    fn check(&mut self, seqno: u32, update_state: bool) -> Result<(), SptpsError> {
        let window_bits = self.window_bytes.saturating_mul(8);

        if window_bits != 0 && seqno != self.expected_seqno {
            let future_cutoff = self
                .expected_seqno
                .saturating_add(u32::try_from(window_bits).unwrap_or(u32::MAX));

            if seqno >= future_cutoff {
                let previous_far_future = self.far_future;

                if update_state {
                    self.far_future = self.far_future.saturating_add(1);
                }

                if previous_far_future < u32::try_from(self.window_bytes >> 2).unwrap_or(u32::MAX) {
                    return Err(SptpsError::FarFuture {
                        seqno,
                        expected_seqno: self.expected_seqno,
                        distance: seqno.saturating_sub(self.expected_seqno),
                        count: if update_state {
                            self.far_future
                        } else {
                            previous_far_future.saturating_add(1)
                        },
                    });
                }

                if update_state {
                    self.late.fill(0xff);
                }
            } else if seqno < self.expected_seqno {
                let outside_window = self.expected_seqno >= window_bits as u32
                    && seqno < self.expected_seqno - window_bits as u32;

                if outside_window || !self.is_marked_late(seqno) {
                    return Err(SptpsError::Replay {
                        seqno,
                        expected_seqno: self.expected_seqno,
                    });
                }
            } else if update_state {
                for missed in self.expected_seqno..seqno {
                    self.mark_late(missed);
                }
            }
        }

        if window_bits != 0 && update_state {
            self.clear_late(seqno);
            self.far_future = 0;
        }

        if update_state {
            if seqno >= self.expected_seqno {
                self.expected_seqno = seqno.wrapping_add(1);
            }

            if self.expected_seqno == 0 {
                self.received = 0;
            } else {
                self.received = self.received.saturating_add(1);
            }
        }

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

impl Default for SptpsReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_SPTPS_REPLAY_WINDOW_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsDatagramCodec {
    in_key: Option<SptpsKey>,
    out_key: Option<SptpsKey>,
    in_replay: SptpsReplayWindow,
    out_seqno: u32,
}

impl SptpsDatagramCodec {
    pub fn new(replay_window_bytes: usize) -> Self {
        Self {
            in_key: None,
            out_key: None,
            in_replay: SptpsReplayWindow::new(replay_window_bytes),
            out_seqno: 0,
        }
    }

    pub fn with_keys(in_key: SptpsKey, out_key: SptpsKey, replay_window_bytes: usize) -> Self {
        Self {
            in_key: Some(in_key),
            out_key: Some(out_key),
            in_replay: SptpsReplayWindow::new(replay_window_bytes),
            out_seqno: 0,
        }
    }

    pub fn from_key_material(
        material: &SptpsKeyMaterial,
        initiator: bool,
        replay_window_bytes: usize,
    ) -> Self {
        let (in_key, out_key) = material.keys_for_role(initiator);
        Self::with_keys(in_key, out_key, replay_window_bytes)
    }

    pub fn set_keys_from_material(&mut self, material: &SptpsKeyMaterial, initiator: bool) {
        let (in_key, out_key) = material.keys_for_role(initiator);
        self.set_in_key(in_key);
        self.set_out_key(out_key);
    }

    pub fn set_in_key(&mut self, key: SptpsKey) {
        self.in_key = Some(key);
    }

    pub fn set_out_key(&mut self, key: SptpsKey) {
        self.out_key = Some(key);
    }

    pub fn clear_in_key(&mut self) {
        self.in_key = None;
        self.in_replay = SptpsReplayWindow::new(self.in_replay.window_bytes());
    }

    pub fn clear_out_key(&mut self) {
        self.out_key = None;
        self.out_seqno = 0;
    }

    pub const fn in_key(&self) -> Option<&SptpsKey> {
        self.in_key.as_ref()
    }

    pub const fn out_key(&self) -> Option<&SptpsKey> {
        self.out_key.as_ref()
    }

    pub fn in_replay(&self) -> &SptpsReplayWindow {
        &self.in_replay
    }

    pub const fn out_seqno(&self) -> u32 {
        self.out_seqno
    }

    pub fn encode(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, SptpsError> {
        validate_record_type(record_type)?;

        let seqno = self.out_seqno;
        self.out_seqno = self.out_seqno.wrapping_add(1);

        let mut body = Vec::with_capacity(1 + payload.len());
        body.push(record_type);
        body.extend_from_slice(payload);

        let mut out = Vec::with_capacity(SPTPS_SEQNO_LEN + body.len() + SPTPS_TAG_LEN);
        out.extend_from_slice(&seqno.to_be_bytes());

        if let Some(key) = &self.out_key {
            out.extend_from_slice(&sptps_chacha_poly1305_encrypt(key, seqno, &body));
        } else {
            out.extend_from_slice(&body);
        }

        Ok(out)
    }

    pub fn decode(&mut self, datagram: &[u8]) -> Result<SptpsRecord, SptpsError> {
        let encrypted = self.in_key.is_some();
        let minimum = if encrypted {
            SPTPS_DATAGRAM_OVERHEAD
        } else {
            SPTPS_SEQNO_LEN + 1
        };

        if datagram.len() < minimum {
            return Err(SptpsError::PacketTooShort {
                minimum,
                actual: datagram.len(),
            });
        }

        let seqno = u32::from_be_bytes(
            datagram[..SPTPS_SEQNO_LEN]
                .try_into()
                .expect("slice length checked"),
        );
        let body = &datagram[SPTPS_SEQNO_LEN..];
        let plaintext = if let Some(key) = &self.in_key {
            let plaintext = sptps_chacha_poly1305_decrypt(key, seqno, body)?;
            self.in_replay.accept(seqno)?;
            plaintext
        } else {
            if seqno != self.in_replay.expected_seqno() {
                return Err(SptpsError::UnexpectedSeqno {
                    expected: self.in_replay.expected_seqno(),
                    actual: seqno,
                });
            }

            self.in_replay.accept(seqno)?;
            body.to_vec()
        };

        let Some((&record_type, payload)) = plaintext.split_first() else {
            return Err(SptpsError::PacketTooShort {
                minimum,
                actual: datagram.len(),
            });
        };
        validate_decoded_record_type(record_type)?;

        if !encrypted && record_type != SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(record_type));
        }

        Ok(SptpsRecord::new(seqno, record_type, payload))
    }

    pub fn verify_datagram(&self, datagram: &[u8]) -> Result<(), SptpsError> {
        let Some(key) = &self.in_key else {
            return Err(SptpsError::AuthenticationFailed);
        };

        if datagram.len() < SPTPS_DATAGRAM_OVERHEAD {
            return Err(SptpsError::PacketTooShort {
                minimum: SPTPS_DATAGRAM_OVERHEAD,
                actual: datagram.len(),
            });
        }

        let seqno = u32::from_be_bytes(
            datagram[..SPTPS_SEQNO_LEN]
                .try_into()
                .expect("slice length checked"),
        );
        self.in_replay.verify(seqno)?;
        sptps_chacha_poly1305_decrypt(key, seqno, &datagram[SPTPS_SEQNO_LEN..])?;
        Ok(())
    }
}

impl Default for SptpsDatagramCodec {
    fn default() -> Self {
        Self::new(DEFAULT_SPTPS_REPLAY_WINDOW_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsTcpCodec {
    in_key: Option<SptpsKey>,
    out_key: Option<SptpsKey>,
    in_seqno: u32,
    out_seqno: u32,
}

impl SptpsTcpCodec {
    pub fn new() -> Self {
        Self {
            in_key: None,
            out_key: None,
            in_seqno: 0,
            out_seqno: 0,
        }
    }

    pub fn with_keys(in_key: SptpsKey, out_key: SptpsKey) -> Self {
        Self {
            in_key: Some(in_key),
            out_key: Some(out_key),
            in_seqno: 0,
            out_seqno: 0,
        }
    }

    pub fn from_key_material(material: &SptpsKeyMaterial, initiator: bool) -> Self {
        let (in_key, out_key) = material.keys_for_role(initiator);
        Self::with_keys(in_key, out_key)
    }

    pub fn set_keys_from_material(&mut self, material: &SptpsKeyMaterial, initiator: bool) {
        let (in_key, out_key) = material.keys_for_role(initiator);
        self.in_key = Some(in_key);
        self.out_key = Some(out_key);
    }

    pub const fn in_key(&self) -> Option<&SptpsKey> {
        self.in_key.as_ref()
    }

    pub const fn out_key(&self) -> Option<&SptpsKey> {
        self.out_key.as_ref()
    }

    pub const fn in_seqno(&self) -> u32 {
        self.in_seqno
    }

    pub const fn out_seqno(&self) -> u32 {
        self.out_seqno
    }

    pub fn encode(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, SptpsError> {
        validate_record_type(record_type)?;
        let length = u16::try_from(payload.len()).map_err(|_| SptpsError::RecordTooLarge {
            maximum: u16::MAX as usize,
            actual: payload.len(),
        })?;
        let seqno = self.out_seqno;
        self.out_seqno = self.out_seqno.wrapping_add(1);

        let mut body = Vec::with_capacity(SPTPS_TCP_HEADER_LEN + payload.len() + SPTPS_TAG_LEN);
        body.extend_from_slice(&length.to_be_bytes());
        body.push(record_type);
        body.extend_from_slice(payload);

        if let Some(key) = &self.out_key {
            let encrypted = sptps_chacha_poly1305_encrypt(key, seqno, &body[2..]);
            body.truncate(2);
            body.extend_from_slice(&encrypted);
        }

        Ok(body)
    }

    pub fn decode(&mut self, record: &[u8]) -> Result<SptpsRecord, SptpsError> {
        if record.len() < SPTPS_TCP_HEADER_LEN {
            return Err(SptpsError::PacketTooShort {
                minimum: SPTPS_TCP_HEADER_LEN,
                actual: record.len(),
            });
        }

        let length = u16::from_be_bytes(
            record[..2]
                .try_into()
                .expect("TCP SPTPS length bytes checked"),
        ) as usize;
        let expected = length
            + if self.in_key.is_some() {
                SPTPS_TCP_AUTH_OVERHEAD
            } else {
                SPTPS_TCP_HEADER_LEN
            };

        if record.len() != expected {
            return Err(SptpsError::InvalidRecordLength {
                expected,
                actual: record.len(),
            });
        }

        let seqno = self.in_seqno;
        let plaintext = if let Some(key) = &self.in_key {
            self.in_seqno = self.in_seqno.wrapping_add(1);
            let mut plaintext = Vec::with_capacity(SPTPS_TCP_HEADER_LEN + length);
            plaintext.extend_from_slice(&record[..2]);
            plaintext.extend_from_slice(&sptps_chacha_poly1305_decrypt(key, seqno, &record[2..])?);
            plaintext
        } else {
            self.in_seqno = self.in_seqno.wrapping_add(1);
            record.to_vec()
        };

        let record_type = plaintext[2];
        validate_decoded_record_type(record_type)?;

        if self.in_key.is_none() && record_type != SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(record_type));
        }

        Ok(SptpsRecord::new(seqno, record_type, &plaintext[3..]))
    }
}

impl Default for SptpsTcpCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SptpsHandshakeEvent {
    HandshakeComplete,
    ApplicationRecord { record_type: u8, payload: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SptpsHandshakeSession {
    initiator: bool,
    label: Vec<u8>,
    my_key: TincEd25519PrivateKey,
    peer_key: TincEd25519PublicKey,
    codec: SptpsHandshakeCodec,
    state: SptpsHandshakeState,
    ecdh: Option<SptpsEphemeralKey>,
    my_kex: Option<SptpsKex>,
    his_kex: Option<SptpsKex>,
    pending_key_material: Option<SptpsKeyMaterial>,
    outbound: VecDeque<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SptpsHandshakeCodec {
    Datagram(SptpsDatagramCodec),
    Tcp(SptpsTcpCodec),
}

impl SptpsHandshakeCodec {
    fn datagram(replay_window_bytes: usize) -> Self {
        Self::Datagram(SptpsDatagramCodec::new(replay_window_bytes))
    }

    fn tcp() -> Self {
        Self::Tcp(SptpsTcpCodec::new())
    }

    fn in_key(&self) -> Option<&SptpsKey> {
        match self {
            Self::Datagram(codec) => codec.in_key(),
            Self::Tcp(codec) => codec.in_key(),
        }
    }

    fn out_key(&self) -> Option<&SptpsKey> {
        match self {
            Self::Datagram(codec) => codec.out_key(),
            Self::Tcp(codec) => codec.out_key(),
        }
    }

    fn set_in_key(&mut self, key: SptpsKey) {
        match self {
            Self::Datagram(codec) => codec.set_in_key(key),
            Self::Tcp(codec) => codec.in_key = Some(key),
        }
    }

    fn set_out_key(&mut self, key: SptpsKey) {
        match self {
            Self::Datagram(codec) => codec.set_out_key(key),
            Self::Tcp(codec) => codec.out_key = Some(key),
        }
    }

    fn encode(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, SptpsError> {
        match self {
            Self::Datagram(codec) => codec.encode(record_type, payload),
            Self::Tcp(codec) => codec.encode(record_type, payload),
        }
    }

    fn decode(&mut self, record: &[u8]) -> Result<SptpsRecord, SptpsError> {
        match self {
            Self::Datagram(codec) => codec.decode(record),
            Self::Tcp(codec) => codec.decode(record),
        }
    }

    fn datagram_codec(&self) -> Option<&SptpsDatagramCodec> {
        match self {
            Self::Datagram(codec) => Some(codec),
            Self::Tcp(_) => None,
        }
    }

    fn datagram_codec_mut(&mut self) -> Option<&mut SptpsDatagramCodec> {
        match self {
            Self::Datagram(codec) => Some(codec),
            Self::Tcp(_) => None,
        }
    }

    fn tcp_codec(&self) -> Option<&SptpsTcpCodec> {
        match self {
            Self::Datagram(_) => None,
            Self::Tcp(codec) => Some(codec),
        }
    }

    fn verify_datagram(&self, datagram: &[u8]) -> Result<(), SptpsError> {
        match self {
            Self::Datagram(codec) => codec.verify_datagram(datagram),
            Self::Tcp(_) => Err(SptpsError::InvalidRecordType(SPTPS_HANDSHAKE)),
        }
    }
}

impl SptpsHandshakeSession {
    pub fn start(
        initiator: bool,
        my_key: TincEd25519PrivateKey,
        peer_key: TincEd25519PublicKey,
        label: impl Into<Vec<u8>>,
        replay_window_bytes: usize,
    ) -> Result<Self, SptpsError> {
        Self::start_with_ephemeral(
            initiator,
            my_key,
            peer_key,
            label,
            replay_window_bytes,
            SptpsEphemeralKey::generate()?,
            random_array()?,
        )
    }

    pub fn start_with_ephemeral(
        initiator: bool,
        my_key: TincEd25519PrivateKey,
        peer_key: TincEd25519PublicKey,
        label: impl Into<Vec<u8>>,
        replay_window_bytes: usize,
        ephemeral: SptpsEphemeralKey,
        nonce: [u8; SPTPS_KEX_NONCE_LEN],
    ) -> Result<Self, SptpsError> {
        let mut session = Self {
            initiator,
            label: label.into(),
            my_key,
            peer_key,
            codec: SptpsHandshakeCodec::datagram(replay_window_bytes),
            state: SptpsHandshakeState::Kex,
            ecdh: None,
            my_kex: None,
            his_kex: None,
            pending_key_material: None,
            outbound: VecDeque::new(),
        };
        session.send_kex_with(ephemeral, nonce)?;
        Ok(session)
    }

    pub fn start_tcp(
        initiator: bool,
        my_key: TincEd25519PrivateKey,
        peer_key: TincEd25519PublicKey,
        label: impl Into<Vec<u8>>,
    ) -> Result<Self, SptpsError> {
        Self::start_tcp_with_ephemeral(
            initiator,
            my_key,
            peer_key,
            label,
            SptpsEphemeralKey::generate()?,
            random_array()?,
        )
    }

    pub fn start_tcp_with_ephemeral(
        initiator: bool,
        my_key: TincEd25519PrivateKey,
        peer_key: TincEd25519PublicKey,
        label: impl Into<Vec<u8>>,
        ephemeral: SptpsEphemeralKey,
        nonce: [u8; SPTPS_KEX_NONCE_LEN],
    ) -> Result<Self, SptpsError> {
        let mut session = Self {
            initiator,
            label: label.into(),
            my_key,
            peer_key,
            codec: SptpsHandshakeCodec::tcp(),
            state: SptpsHandshakeState::Kex,
            ecdh: None,
            my_kex: None,
            his_kex: None,
            pending_key_material: None,
            outbound: VecDeque::new(),
        };
        session.send_kex_with(ephemeral, nonce)?;
        Ok(session)
    }

    pub const fn initiator(&self) -> bool {
        self.initiator
    }

    pub const fn state(&self) -> SptpsHandshakeState {
        self.state
    }

    pub fn codec(&self) -> &SptpsDatagramCodec {
        self.codec
            .datagram_codec()
            .expect("SPTPS session uses datagram records")
    }

    pub fn codec_mut(&mut self) -> &mut SptpsDatagramCodec {
        self.codec
            .datagram_codec_mut()
            .expect("SPTPS session uses datagram records")
    }

    pub fn tcp_codec(&self) -> &SptpsTcpCodec {
        self.codec
            .tcp_codec()
            .expect("SPTPS session uses TCP records")
    }

    pub fn is_established(&self) -> bool {
        self.codec.in_key().is_some() && self.codec.out_key().is_some()
    }

    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn send_record(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, SptpsError> {
        if record_type >= SPTPS_HANDSHAKE {
            return Err(SptpsError::InvalidRecordType(record_type));
        }

        self.codec.encode(record_type, payload)
    }

    pub fn verify_datagram(&self, datagram: &[u8]) -> Result<(), SptpsError> {
        self.codec.verify_datagram(datagram)
    }

    pub fn receive_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<SptpsHandshakeEvent>, SptpsError> {
        let record = self.codec.decode(datagram)?;

        if record.record_type == SPTPS_HANDSHAKE {
            self.receive_handshake(&record.payload)
        } else if record.record_type < SPTPS_HANDSHAKE {
            Ok(vec![SptpsHandshakeEvent::ApplicationRecord {
                record_type: record.record_type,
                payload: record.payload,
            }])
        } else {
            Err(SptpsError::InvalidRecordType(record.record_type))
        }
    }

    pub fn force_kex(&mut self) -> Result<(), SptpsError> {
        if !self.is_established() || self.state != SptpsHandshakeState::SecondaryKex {
            return Err(SptpsError::UnexpectedHandshakeRecord {
                state: self.state,
                len: 0,
            });
        }

        self.state = SptpsHandshakeState::Kex;
        self.send_kex()
    }

    fn receive_handshake(&mut self, data: &[u8]) -> Result<Vec<SptpsHandshakeEvent>, SptpsError> {
        match self.state {
            SptpsHandshakeState::SecondaryKex => {
                self.send_kex()?;
                self.receive_kex(data)?;
                self.state = SptpsHandshakeState::Sig;
                Ok(Vec::new())
            }
            SptpsHandshakeState::Kex => {
                self.receive_kex(data)?;
                self.state = SptpsHandshakeState::Sig;
                Ok(Vec::new())
            }
            SptpsHandshakeState::Sig => {
                let secondary = self.receive_sig(data)?;

                if secondary {
                    self.state = SptpsHandshakeState::Ack;
                    Ok(Vec::new())
                } else {
                    self.state = SptpsHandshakeState::SecondaryKex;
                    Ok(vec![SptpsHandshakeEvent::HandshakeComplete])
                }
            }
            SptpsHandshakeState::Ack => {
                self.receive_ack(data)?;
                self.state = SptpsHandshakeState::SecondaryKex;
                Ok(vec![SptpsHandshakeEvent::HandshakeComplete])
            }
        }
    }

    fn receive_kex(&mut self, data: &[u8]) -> Result<(), SptpsError> {
        if self.his_kex.is_some() {
            return Err(SptpsError::DuplicateKex);
        }

        self.his_kex = Some(SptpsKex::try_from_slice(data)?);

        if self.initiator {
            self.send_sig()?;
        }

        Ok(())
    }

    fn receive_sig(&mut self, data: &[u8]) -> Result<bool, SptpsError> {
        if data.len() != ED25519_SIGNATURE_LEN {
            return Err(SptpsError::InvalidSignatureLength {
                expected: ED25519_SIGNATURE_LEN,
                actual: data.len(),
            });
        }

        let his_kex = self
            .his_kex
            .ok_or(SptpsError::MissingHandshakeState("peer KEX"))?;
        let my_kex = self
            .my_kex
            .ok_or(SptpsError::MissingHandshakeState("local KEX"))?;
        let message = sptps_signature_message(!self.initiator, &his_kex, &my_kex, &self.label);
        self.peer_key.verify(&message, data)?;

        let shared = self
            .ecdh
            .as_ref()
            .ok_or(SptpsError::MissingHandshakeState("ephemeral key"))?
            .compute_shared(&his_kex.public_key)?;
        let (initiator_nonce, responder_nonce) = if self.initiator {
            (&my_kex.nonce, &his_kex.nonce)
        } else {
            (&his_kex.nonce, &my_kex.nonce)
        };
        let material =
            SptpsKeyMaterial::derive(&shared, initiator_nonce, responder_nonce, &self.label);
        let secondary = self.codec.out_key().is_some();

        if !self.initiator {
            self.send_sig()?;
        }

        self.ecdh = None;
        self.my_kex = None;
        self.his_kex = None;

        if secondary {
            self.queue_handshake(&[])?;
            self.pending_key_material = Some(material.clone());
        }

        let (in_key, out_key) = material.keys_for_role(self.initiator);
        self.codec.set_out_key(out_key);

        if !secondary {
            self.codec.set_in_key(in_key);
        }

        Ok(secondary)
    }

    fn receive_ack(&mut self, data: &[u8]) -> Result<(), SptpsError> {
        if !data.is_empty() {
            return Err(SptpsError::UnexpectedHandshakeRecord {
                state: self.state,
                len: data.len(),
            });
        }

        let material = self
            .pending_key_material
            .take()
            .ok_or(SptpsError::MissingHandshakeState("pending key material"))?;
        let (in_key, _) = material.keys_for_role(self.initiator);
        self.codec.set_in_key(in_key);
        Ok(())
    }

    fn send_kex(&mut self) -> Result<(), SptpsError> {
        self.send_kex_with(SptpsEphemeralKey::generate()?, random_array()?)
    }

    fn send_kex_with(
        &mut self,
        ephemeral: SptpsEphemeralKey,
        nonce: [u8; SPTPS_KEX_NONCE_LEN],
    ) -> Result<(), SptpsError> {
        if self.my_kex.is_some() {
            return Err(SptpsError::DuplicateKex);
        }

        let public_key = *ephemeral.public_key();
        let kex = SptpsKex::new(nonce, public_key);
        self.ecdh = Some(ephemeral);
        self.my_kex = Some(kex);
        self.queue_handshake(&kex.to_bytes())
    }

    fn send_sig(&mut self) -> Result<(), SptpsError> {
        let my_kex = self
            .my_kex
            .ok_or(SptpsError::MissingHandshakeState("local KEX"))?;
        let his_kex = self
            .his_kex
            .ok_or(SptpsError::MissingHandshakeState("peer KEX"))?;
        let message = sptps_signature_message(self.initiator, &my_kex, &his_kex, &self.label);
        let signature = self.my_key.sign(&message);
        self.queue_handshake(&signature)
    }

    fn queue_handshake(&mut self, payload: &[u8]) -> Result<(), SptpsError> {
        self.outbound
            .push_back(self.codec.encode(SPTPS_HANDSHAKE, payload)?);
        Ok(())
    }
}

fn validate_record_type(record_type: u8) -> Result<(), SptpsError> {
    if record_type > SPTPS_HANDSHAKE {
        return Err(SptpsError::InvalidRecordType(record_type));
    }

    Ok(())
}

fn validate_decoded_record_type(record_type: u8) -> Result<(), SptpsError> {
    if record_type <= SPTPS_HANDSHAKE {
        Ok(())
    } else {
        Err(SptpsError::InvalidRecordType(record_type))
    }
}

fn sptps_chacha_poly1305_encrypt(key: &SptpsKey, seqno: u32, plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = plaintext.to_vec();
    let poly_key = chacha20_block(key, seqno, 0, 32);
    chacha20_xor_in_place(key, seqno, 1, &mut ciphertext);

    let tag = poly1305_tag(&poly_key, &ciphertext);
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

fn sptps_chacha_poly1305_decrypt(
    key: &SptpsKey,
    seqno: u32,
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, SptpsError> {
    if ciphertext_and_tag.len() < SPTPS_TAG_LEN {
        return Err(SptpsError::PacketTooShort {
            minimum: SPTPS_TAG_LEN,
            actual: ciphertext_and_tag.len(),
        });
    }

    let ciphertext_len = ciphertext_and_tag.len() - SPTPS_TAG_LEN;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_len);
    let poly_key = chacha20_block(key, seqno, 0, 32);
    let expected = poly1305_tag(&poly_key, ciphertext);

    if !constant_time_eq(&expected, tag) {
        return Err(SptpsError::AuthenticationFailed);
    }

    let mut plaintext = ciphertext.to_vec();
    chacha20_xor_in_place(key, seqno, 1, &mut plaintext);
    Ok(plaintext)
}

fn chacha20_block(key: &SptpsKey, seqno: u32, counter: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    chacha20_xor_in_place(key, seqno, counter, &mut out);
    out
}

fn chacha20_xor_in_place(key: &SptpsKey, seqno: u32, counter: u64, data: &mut [u8]) {
    let nonce = seqno.to_be_bytes();
    let mut nonce64 = [0; 8];
    nonce64[4..].copy_from_slice(&nonce);
    let mut cipher = ChaCha20Legacy::new(key.chacha_key().into(), (&nonce64).into());
    cipher.seek(counter.saturating_mul(64));
    cipher.apply_keystream(data);
}

fn poly1305_tag(key: &[u8], message: &[u8]) -> [u8; SPTPS_TAG_LEN] {
    let key = Poly1305Key::from_slice(key);
    let tag = Poly1305::new(key).compute_unpadded(message);
    let mut out = [0; SPTPS_TAG_LEN];
    out.copy_from_slice(&tag);
    out
}

pub fn sptps_prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut data = vec![0; SPTPS_PRF_DIGEST_LEN + seed.len()];
    data[SPTPS_PRF_DIGEST_LEN..].copy_from_slice(seed);
    let mut offset = 0;

    while offset < out.len() {
        let inner = hmac_sha512(secret, &data);
        data[..SPTPS_PRF_DIGEST_LEN].copy_from_slice(&inner);
        let hash = hmac_sha512(secret, &data);
        let take = (out.len() - offset).min(SPTPS_PRF_DIGEST_LEN);
        out[offset..offset + take].copy_from_slice(&hash[..take]);
        offset += take;
    }
}

fn hmac_sha512(secret: &[u8], data: &[u8]) -> [u8; SPTPS_PRF_DIGEST_LEN] {
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0; SPTPS_PRF_DIGEST_LEN];
    out.copy_from_slice(&tag);
    out
}

fn ed25519_hram(
    r: &[u8; ED25519_PUBLIC_KEY_LEN],
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(public_key);
    hasher.update(message);
    Scalar::from_bytes_mod_order_wide(&digest_to_array(hasher.finalize()))
}

fn sha512_digest(message: &[u8]) -> [u8; SPTPS_PRF_DIGEST_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    digest_to_array(hasher.finalize())
}

fn digest_to_array(digest: impl AsRef<[u8]>) -> [u8; SPTPS_PRF_DIGEST_LEN] {
    digest
        .as_ref()
        .try_into()
        .expect("SHA512 digest is always 64 bytes")
}

fn clamp_ed25519_scalar(bytes: &mut [u8]) {
    bytes[0] &= 248;
    bytes[31] &= 63;
    bytes[31] |= 64;
}

fn random_array<const N: usize>() -> Result<[u8; N], SptpsError> {
    let mut out = [0; N];
    getrandom::getrandom(&mut out).map_err(|error| SptpsError::RandomFailed(error.to_string()))?;
    Ok(out)
}

fn read_tinc_pem(
    input: &str,
    pem_type: &'static str,
    expected_len: usize,
) -> Result<Vec<u8>, SptpsError> {
    let begin = format!("-----BEGIN {pem_type}-----");
    let end = format!("-----END {pem_type}-----");
    let mut in_data = false;
    let mut out = Vec::with_capacity(expected_len);

    for line in input.lines() {
        let line = line.trim_end_matches('\r');

        if !in_data {
            if line == begin {
                in_data = true;
            }
            continue;
        }

        if line == end {
            return if out.len() == expected_len {
                Ok(out)
            } else {
                Err(SptpsError::InvalidPem { pem_type })
            };
        }

        let chunk = b64decode_tinc(line).map_err(SptpsError::InvalidPemBase64)?;

        if chunk.is_empty() || out.len() + chunk.len() > expected_len {
            return Err(SptpsError::InvalidPem { pem_type });
        }

        out.extend_from_slice(&chunk);
    }

    Err(SptpsError::InvalidPem { pem_type })
}

fn write_tinc_pem(pem_type: &str, data: &[u8]) -> String {
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(pem_type);
    out.push_str("-----\n");

    for chunk in data.chunks(TINC_PEM_CHUNK_LEN) {
        out.push_str(&b64encode_tinc(chunk));
        out.push('\n');
    }

    out.push_str("-----END ");
    out.push_str(pem_type);
    out.push_str("-----\n");
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right)
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use tinc_core::utils::hex_to_bin;

    use super::*;

    fn key(byte: u8) -> SptpsKey {
        SptpsKey::new([byte; SPTPS_KEY_LEN])
    }

    fn tinc_key(seed_byte: u8) -> TincEd25519PrivateKey {
        TincEd25519PrivateKey::from_seed([seed_byte; ED25519_SEED_LEN])
    }

    fn ephemeral(seed_byte: u8) -> SptpsEphemeralKey {
        SptpsEphemeralKey::from_seed([seed_byte; ED25519_SEED_LEN])
    }

    fn nonce(byte: u8) -> [u8; SPTPS_KEX_NONCE_LEN] {
        [byte; SPTPS_KEX_NONCE_LEN]
    }

    fn move_one_handshake(
        sender: &mut SptpsHandshakeSession,
        receiver: &mut SptpsHandshakeSession,
    ) -> Vec<SptpsHandshakeEvent> {
        let packet = sender.pop_outbound().expect("sender has a packet queued");
        receiver.receive_datagram(&packet).unwrap()
    }

    fn move_one_tcp_handshake(
        sender: &mut SptpsHandshakeSession,
        receiver: &mut SptpsHandshakeSession,
    ) -> Vec<SptpsHandshakeEvent> {
        let packet = sender.pop_outbound().expect("sender has a packet queued");
        receiver.receive_datagram(&packet).unwrap()
    }

    fn establish_test_sessions() -> (SptpsHandshakeSession, SptpsHandshakeSession) {
        let initiator_key = tinc_key(1);
        let responder_key = tinc_key(2);
        let label = b"tinc UDP key expansion alice bob";
        let mut initiator = SptpsHandshakeSession::start_with_ephemeral(
            true,
            initiator_key.clone(),
            responder_key.public_key(),
            label,
            16,
            ephemeral(3),
            nonce(4),
        )
        .unwrap();
        let mut responder = SptpsHandshakeSession::start_with_ephemeral(
            false,
            responder_key,
            initiator_key.public_key(),
            label,
            16,
            ephemeral(5),
            nonce(6),
        )
        .unwrap();

        assert!(move_one_handshake(&mut initiator, &mut responder).is_empty());
        assert!(move_one_handshake(&mut responder, &mut initiator).is_empty());
        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_handshake(&mut initiator, &mut responder)
        );
        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_handshake(&mut responder, &mut initiator)
        );
        assert!(initiator.drain_outbound().is_empty());
        assert!(responder.drain_outbound().is_empty());

        (initiator, responder)
    }

    #[test]
    fn sptps_key_requires_64_bytes() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(Ok(key(7)), SptpsKey::try_from_slice(&[7; SPTPS_KEY_LEN]));
        assert!(matches!(
            SptpsKey::try_from_slice(&[7; SPTPS_KEY_LEN - 1]),
            Err(SptpsError::InvalidKeyLength {
                expected: SPTPS_KEY_LEN,
                actual,
            }) if actual == SPTPS_KEY_LEN - 1
        ));
    }

    #[test]
    fn sptps_key_material_requires_128_bytes() {
        tinc_test_support::assert_can_create_netns();
        let bytes = [9; SPTPS_KEY_MATERIAL_LEN];
        assert_eq!(
            Ok(SptpsKeyMaterial::new(bytes)),
            SptpsKeyMaterial::try_from_slice(&bytes)
        );
        assert!(matches!(
            SptpsKeyMaterial::try_from_slice(&bytes[..SPTPS_KEY_MATERIAL_LEN - 1]),
            Err(SptpsError::InvalidKeyMaterialLength {
                expected: SPTPS_KEY_MATERIAL_LEN,
                actual,
            }) if actual == SPTPS_KEY_MATERIAL_LEN - 1
        ));
    }

    #[test]
    fn tinc_ed25519_keys_sign_verify_and_roundtrip_private_file_payload() {
        tinc_test_support::assert_can_create_netns();
        let key = tinc_key(9);
        let message = b"SPTPS signature payload";
        let signature = key.sign(message);

        key.public_key().verify(message, &signature).unwrap();
        assert_eq!(
            Err(SptpsError::SignatureVerificationFailed),
            key.public_key().verify(b"tampered", &signature)
        );

        let payload = key.as_tinc_private_key();
        let decoded = TincEd25519PrivateKey::try_from_tinc_private_key(&payload).unwrap();
        assert_eq!(key, decoded);
        assert!(matches!(
            TincEd25519PrivateKey::try_from_tinc_private_key(&payload[..payload.len() - 1]),
            Err(SptpsError::InvalidPrivateKeyLength {
                expected: ED25519_TINC_PRIVATE_KEY_LEN,
                actual,
            }) if actual == ED25519_TINC_PRIVATE_KEY_LEN - 1
        ));
    }

    #[test]
    fn tinc_ed25519_keys_roundtrip_base64_and_pem_formats() {
        tinc_test_support::assert_can_create_netns();
        let key = tinc_key(10);
        let public = key.public_key();
        let public_base64 = public.to_base64();

        assert_eq!(ED25519_PUBLIC_KEY_BASE64_LEN, public_base64.len());
        assert_eq!(
            Ok(public),
            TincEd25519PublicKey::from_base64(&public_base64)
        );
        assert!(matches!(
            TincEd25519PublicKey::from_base64(&public_base64[..public_base64.len() - 1]),
            Err(SptpsError::InvalidPublicKeyBase64Length {
                expected: ED25519_PUBLIC_KEY_BASE64_LEN,
                actual,
            }) if actual == ED25519_PUBLIC_KEY_BASE64_LEN - 1
        ));

        let public_pem = public.to_pem();
        assert!(public_pem.starts_with("-----BEGIN ED25519 PUBLIC KEY-----\n"));
        assert!(public_pem.ends_with("-----END ED25519 PUBLIC KEY-----\n"));
        assert_eq!(Ok(public), TincEd25519PublicKey::from_pem(&public_pem));

        let private_pem = key.to_pem();
        let private_lines: Vec<_> = private_pem.lines().collect();
        assert_eq!("-----BEGIN ED25519 PRIVATE KEY-----", private_lines[0]);
        assert_eq!(64, private_lines[1].len());
        assert_eq!(64, private_lines[2].len());
        assert_eq!("-----END ED25519 PRIVATE KEY-----", private_lines[3]);
        assert_eq!(
            Ok(key.clone()),
            TincEd25519PrivateKey::from_pem(&private_pem)
        );

        assert!(matches!(
            TincEd25519PrivateKey::from_pem(
                "-----BEGIN ED25519 PRIVATE KEY-----\n????\n-----END ED25519 PRIVATE KEY-----\n"
            ),
            Err(SptpsError::InvalidPemBase64(_))
        ));
        assert_eq!(
            Err(SptpsError::InvalidPem {
                pem_type: ED25519_PRIVATE_PEM_TYPE,
            }),
            TincEd25519PrivateKey::from_pem(
                "-----BEGIN ED25519 PRIVATE KEY-----\nhJ2Y\n-----END ED25519 PRIVATE KEY-----\n"
            )
        );
    }

    #[test]
    fn sptps_ephemeral_key_exchange_is_symmetric_and_uses_ed25519_public_keys() {
        tinc_test_support::assert_can_create_netns();
        let left = ephemeral(11);
        let right = ephemeral(12);

        assert_eq!(
            left.compute_shared(right.public_key()).unwrap(),
            right.compute_shared(left.public_key()).unwrap()
        );
        assert_ne!(
            [0; SPTPS_KEX_PUBKEY_LEN],
            left.compute_shared(right.public_key()).unwrap()
        );
    }

    #[test]
    fn sptps_kex_is_65_byte_version_nonce_public_key_record() {
        tinc_test_support::assert_can_create_netns();
        let kex = SptpsKex::new(nonce(0xaa), *ephemeral(7).public_key());
        let bytes = kex.to_bytes();

        assert_eq!(SPTPS_KEX_LEN, bytes.len());
        assert_eq!(SPTPS_VERSION, bytes[0]);
        assert_eq!(&[0xaa; SPTPS_KEX_NONCE_LEN], &bytes[1..33]);
        assert_eq!(Ok(kex), SptpsKex::try_from_slice(&bytes));

        let mut wrong_version = bytes;
        wrong_version[0] = 1;
        assert_eq!(
            Err(SptpsError::InvalidKexVersion(1)),
            SptpsKex::try_from_slice(&wrong_version)
        );
        assert!(matches!(
            SptpsKex::try_from_slice(&wrong_version[..SPTPS_KEX_LEN - 1]),
            Err(SptpsError::InvalidKexLength {
                expected: SPTPS_KEX_LEN,
                actual,
            }) if actual == SPTPS_KEX_LEN - 1
        ));
    }

    #[test]
    fn sptps_signature_message_matches_c_fill_msg_shape() {
        tinc_test_support::assert_can_create_netns();
        let kex0 = SptpsKex::new(nonce(1), [2; SPTPS_KEX_PUBKEY_LEN]);
        let kex1 = SptpsKex::new(nonce(3), [4; SPTPS_KEX_PUBKEY_LEN]);
        let label = b"label";
        let message = sptps_signature_message(true, &kex0, &kex1, label);

        assert_eq!(1 + SPTPS_KEX_LEN * 2 + label.len(), message.len());
        assert_eq!(1, message[0]);
        assert_eq!(&kex0.to_bytes(), &message[1..1 + SPTPS_KEX_LEN]);
        assert_eq!(
            &kex1.to_bytes(),
            &message[1 + SPTPS_KEX_LEN..1 + SPTPS_KEX_LEN * 2]
        );
        assert_eq!(label, &message[1 + SPTPS_KEX_LEN * 2..]);
    }

    #[test]
    fn sptps_key_material_derivation_matches_c_prf_vector() {
        tinc_test_support::assert_can_create_netns();
        let shared: Vec<u8> = (0..32).collect();
        let initiator_nonce: [u8; SPTPS_KEX_NONCE_LEN] =
            std::array::from_fn(|index| 0xa0 + index as u8);
        let responder_nonce: [u8; SPTPS_KEX_NONCE_LEN] =
            std::array::from_fn(|index| 0xc0 + index as u8);
        let label = b"tinc UDP key expansion myself alpha";
        let expected = hex_to_bin(
            concat!(
                "8800508a029c28fcd51a430a4508f4f2cee30f1b0d432c9d9029171cde79eeab",
                "d7271ef86a4c0885de958e87908b15d178e8e029b756e0f1089a4f5782c0",
                "f14eeed1269ea4d10ee8a19efd807c6afc0efad3857b54b89e11424dc3c",
                "996aed3d08904ac0cd924816fe5e246b59b79ead05336593539324ea10d",
                "62f547411b28fe"
            ),
            SPTPS_KEY_MATERIAL_LEN,
        );

        let material = SptpsKeyMaterial::derive(&shared, &initiator_nonce, &responder_nonce, label);

        assert_eq!(expected, material.as_bytes());
        let (initiator_in, initiator_out) = material.keys_for_role(true);
        let (responder_in, responder_out) = material.keys_for_role(false);
        assert_eq!(material.key0, initiator_in);
        assert_eq!(material.key1, initiator_out);
        assert_eq!(initiator_out, responder_in);
        assert_eq!(initiator_in, responder_out);
    }

    #[test]
    fn sptps_handshake_session_establishes_keys_and_exchanges_application_records() {
        tinc_test_support::assert_can_create_netns();
        let (mut initiator, mut responder) = establish_test_sessions();

        assert!(initiator.is_established());
        assert!(responder.is_established());
        assert_eq!(SptpsHandshakeState::SecondaryKex, initiator.state());
        assert_eq!(SptpsHandshakeState::SecondaryKex, responder.state());

        let packet = initiator.send_record(2, b"payload").unwrap();
        responder.verify_datagram(&packet).unwrap();
        assert_eq!(
            vec![SptpsHandshakeEvent::ApplicationRecord {
                record_type: 2,
                payload: b"payload".to_vec(),
            }],
            responder.receive_datagram(&packet).unwrap()
        );

        let reply = responder.send_record(3, b"reply").unwrap();
        assert_eq!(
            vec![SptpsHandshakeEvent::ApplicationRecord {
                record_type: 3,
                payload: b"reply".to_vec(),
            }],
            initiator.receive_datagram(&reply).unwrap()
        );
    }

    #[test]
    fn sptps_tcp_handshake_session_establishes_keys_and_exchanges_application_records() {
        tinc_test_support::assert_can_create_netns();
        let initiator_key = tinc_key(1);
        let responder_key = tinc_key(2);
        let label = b"tinc TCP key expansion alice bob\0";
        let mut initiator = SptpsHandshakeSession::start_tcp_with_ephemeral(
            true,
            initiator_key.clone(),
            responder_key.public_key(),
            label,
            ephemeral(3),
            nonce(4),
        )
        .unwrap();
        let mut responder = SptpsHandshakeSession::start_tcp_with_ephemeral(
            false,
            responder_key,
            initiator_key.public_key(),
            label,
            ephemeral(5),
            nonce(6),
        )
        .unwrap();

        assert!(move_one_tcp_handshake(&mut initiator, &mut responder).is_empty());
        assert!(move_one_tcp_handshake(&mut responder, &mut initiator).is_empty());
        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_tcp_handshake(&mut initiator, &mut responder)
        );
        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_tcp_handshake(&mut responder, &mut initiator)
        );
        assert!(initiator.is_established());
        assert!(responder.is_established());
        assert_eq!(2, initiator.tcp_codec().out_seqno());
        assert_eq!(2, responder.tcp_codec().out_seqno());

        let packet = initiator.send_record(2, b"payload").unwrap();
        assert_eq!(
            vec![SptpsHandshakeEvent::ApplicationRecord {
                record_type: 2,
                payload: b"payload".to_vec(),
            }],
            responder.receive_datagram(&packet).unwrap()
        );
    }

    #[test]
    fn sptps_handshake_session_performs_secondary_key_exchange_with_ack() {
        tinc_test_support::assert_can_create_netns();
        let (mut initiator, mut responder) = establish_test_sessions();
        let old_initiator_in = initiator.codec().in_key().cloned();
        let old_initiator_out = initiator.codec().out_key().cloned();
        let old_responder_in = responder.codec().in_key().cloned();
        let old_responder_out = responder.codec().out_key().cloned();

        initiator.force_kex().unwrap();
        assert!(move_one_handshake(&mut initiator, &mut responder).is_empty());
        assert!(move_one_handshake(&mut responder, &mut initiator).is_empty());
        assert!(move_one_handshake(&mut initiator, &mut responder).is_empty());
        assert_eq!(SptpsHandshakeState::Ack, responder.state());
        assert_eq!(old_responder_in, responder.codec().in_key().cloned());
        assert_ne!(old_responder_out, responder.codec().out_key().cloned());

        assert!(move_one_handshake(&mut responder, &mut initiator).is_empty());
        assert_eq!(SptpsHandshakeState::Ack, initiator.state());
        assert_eq!(old_initiator_in, initiator.codec().in_key().cloned());
        assert_ne!(old_initiator_out, initiator.codec().out_key().cloned());

        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_handshake(&mut initiator, &mut responder)
        );
        assert_eq!(
            vec![SptpsHandshakeEvent::HandshakeComplete],
            move_one_handshake(&mut responder, &mut initiator)
        );
        assert_ne!(old_initiator_in, initiator.codec().in_key().cloned());
        assert_ne!(old_responder_in, responder.codec().in_key().cloned());

        let packet = initiator.send_record(4, b"new-key-packet").unwrap();
        assert_eq!(
            vec![SptpsHandshakeEvent::ApplicationRecord {
                record_type: 4,
                payload: b"new-key-packet".to_vec(),
            }],
            responder.receive_datagram(&packet).unwrap()
        );
    }

    #[test]
    fn sptps_handshake_rejects_bad_peer_signature() {
        tinc_test_support::assert_can_create_netns();
        let initiator_key = tinc_key(21);
        let responder_key = tinc_key(22);
        let label = b"tinc UDP key expansion alice bob";
        let mut initiator = SptpsHandshakeSession::start_with_ephemeral(
            true,
            initiator_key.clone(),
            responder_key.public_key(),
            label,
            16,
            ephemeral(23),
            nonce(24),
        )
        .unwrap();
        let mut responder = SptpsHandshakeSession::start_with_ephemeral(
            false,
            responder_key,
            initiator_key.public_key(),
            label,
            16,
            ephemeral(25),
            nonce(26),
        )
        .unwrap();

        assert!(move_one_handshake(&mut initiator, &mut responder).is_empty());
        assert!(move_one_handshake(&mut responder, &mut initiator).is_empty());

        let mut sig = initiator.pop_outbound().unwrap();
        *sig.last_mut().unwrap() ^= 1;
        assert_eq!(
            Err(SptpsError::SignatureVerificationFailed),
            responder.receive_datagram(&sig)
        );
    }

    #[test]
    fn sptps_datagram_codec_uses_role_keys_from_key_material() {
        tinc_test_support::assert_can_create_netns();
        let material = SptpsKeyMaterial::new(std::array::from_fn(|index| index as u8));
        let mut initiator = SptpsDatagramCodec::from_key_material(&material, true, 16);
        let mut responder = SptpsDatagramCodec::from_key_material(&material, false, 16);

        let request = initiator.encode(4, b"request").unwrap();
        let decoded = responder.decode(&request).unwrap();
        assert_eq!(SptpsRecord::new(0, 4, b"request"), decoded);

        let response = responder.encode(5, b"response").unwrap();
        let decoded = initiator.decode(&response).unwrap();
        assert_eq!(SptpsRecord::new(0, 5, b"response"), decoded);
    }

    #[test]
    fn plaintext_datagram_records_are_sequence_type_payload() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = SptpsDatagramCodec::default();
        let encoded = codec.encode(SPTPS_HANDSHAKE, b"kex").unwrap();

        assert_eq!(&0u32.to_be_bytes(), &encoded[..SPTPS_SEQNO_LEN]);
        assert_eq!(SPTPS_HANDSHAKE, encoded[SPTPS_SEQNO_LEN]);
        assert_eq!(b"kex", &encoded[SPTPS_SEQNO_LEN + 1..]);

        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(SptpsRecord::new(0, SPTPS_HANDSHAKE, b"kex"), decoded);
        assert_eq!(1, codec.in_replay().expected_seqno());
    }

    #[test]
    fn plaintext_datagram_rejects_application_records_and_bad_sequence() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = SptpsDatagramCodec::default();
        let mut app = Vec::new();
        app.extend_from_slice(&0u32.to_be_bytes());
        app.push(1);
        app.extend_from_slice(b"app");
        assert_eq!(Err(SptpsError::InvalidRecordType(1)), codec.decode(&app));
        assert_eq!(1, codec.in_replay().expected_seqno());

        let mut seq = Vec::new();
        seq.extend_from_slice(&2u32.to_be_bytes());
        seq.push(SPTPS_HANDSHAKE);
        assert_eq!(
            Err(SptpsError::UnexpectedSeqno {
                expected: 1,
                actual: 2,
            }),
            codec.decode(&seq)
        );
    }

    #[test]
    fn encrypted_datagram_records_roundtrip_and_count_overhead() {
        tinc_test_support::assert_can_create_netns();
        let key = key(3);
        let mut sender = SptpsDatagramCodec::with_keys(key.clone(), key.clone(), 16);
        let mut receiver = SptpsDatagramCodec::with_keys(key.clone(), key, 16);

        let encoded = sender.encode(2, b"payload").unwrap();

        assert_eq!(SPTPS_DATAGRAM_OVERHEAD + b"payload".len(), encoded.len());
        assert_eq!(&0u32.to_be_bytes(), &encoded[..SPTPS_SEQNO_LEN]);
        assert_ne!(2, encoded[SPTPS_SEQNO_LEN]);
        receiver.verify_datagram(&encoded).unwrap();
        assert_eq!(0, receiver.in_replay().expected_seqno());

        let decoded = receiver.decode(&encoded).unwrap();

        assert_eq!(SptpsRecord::new(0, 2, b"payload"), decoded);
        assert_eq!(1, receiver.in_replay().expected_seqno());
        assert_eq!(1, receiver.in_replay().received());
    }

    #[test]
    fn encrypted_datagram_matches_c_chacha_poly1305_vectors() {
        tinc_test_support::assert_can_create_netns();
        let key = key(3);
        let mut codec = SptpsDatagramCodec::with_keys(key.clone(), key, 16);

        assert_eq!(
            hex_to_bin(
                "00000000fdc985970a9ac3673a643b5a5bbb10db3d50bb4c97f93ef2",
                256
            ),
            codec.encode(2, b"payload").unwrap()
        );
        assert_eq!(
            hex_to_bin(
                "0000000145f0700503a88e8385eaf9b70a492b454f5266663bc61d82",
                256
            ),
            codec.encode(2, b"payload").unwrap()
        );
    }

    #[test]
    fn tcp_codec_encodes_plain_handshake_records_like_c_sptps() {
        tinc_test_support::assert_can_create_netns();
        let mut codec = SptpsTcpCodec::new();
        let encoded = codec.encode(SPTPS_HANDSHAKE, b"kex").unwrap();

        assert_eq!(vec![0, 3, SPTPS_HANDSHAKE, b'k', b'e', b'x'], encoded);
        assert_eq!(
            SptpsRecord::new(0, SPTPS_HANDSHAKE, b"kex"),
            codec.decode(&encoded).unwrap()
        );
        assert_eq!(1, codec.in_seqno());
        assert_eq!(1, codec.out_seqno());
    }

    #[test]
    fn tcp_codec_encrypts_records_without_wire_sequence_numbers() {
        tinc_test_support::assert_can_create_netns();
        let key = key(3);
        let mut sender = SptpsTcpCodec::with_keys(key.clone(), key.clone());
        let mut receiver = SptpsTcpCodec::with_keys(key.clone(), key);

        let encoded = sender.encode(2, b"payload").unwrap();
        assert_eq!(2 + 1 + b"payload".len() + SPTPS_TAG_LEN, encoded.len());
        assert_eq!([0, 7], encoded[..2]);
        assert_ne!(2, encoded[2]);
        assert_eq!(1, sender.out_seqno());

        assert_eq!(
            SptpsRecord::new(0, 2, b"payload"),
            receiver.decode(&encoded).unwrap()
        );
        assert_eq!(1, receiver.in_seqno());
    }

    #[test]
    fn tcp_codec_rejects_tampering_and_bad_lengths() {
        tinc_test_support::assert_can_create_netns();
        let key = key(4);
        let mut sender = SptpsTcpCodec::with_keys(key.clone(), key.clone());
        let mut receiver = SptpsTcpCodec::with_keys(key.clone(), key);
        let encoded = sender.encode(3, b"payload").unwrap();

        let mut tampered = encoded.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            Err(SptpsError::AuthenticationFailed),
            receiver.decode(&tampered)
        );
        assert_eq!(
            Err(SptpsError::InvalidRecordLength {
                expected: encoded.len(),
                actual: encoded.len() - 1
            }),
            receiver.decode(&encoded[..encoded.len() - 1])
        );

        let mut plain = SptpsTcpCodec::new();
        assert_eq!(
            Err(SptpsError::InvalidRecordLength {
                expected: 4,
                actual: 3
            }),
            plain.decode(&[0, 1, SPTPS_HANDSHAKE])
        );
    }

    #[test]
    fn encrypted_datagram_rejects_tampering_and_replay() {
        tinc_test_support::assert_can_create_netns();
        let key = key(4);
        let mut sender = SptpsDatagramCodec::with_keys(key.clone(), key.clone(), 16);
        let mut receiver = SptpsDatagramCodec::with_keys(key.clone(), key, 16);
        let encoded = sender.encode(3, b"payload").unwrap();

        let mut tampered = encoded.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            Err(SptpsError::AuthenticationFailed),
            receiver.decode(&tampered)
        );

        receiver.decode(&encoded).unwrap();
        assert!(matches!(
            receiver.decode(&encoded),
            Err(SptpsError::Replay { seqno: 0, .. })
        ));
    }

    #[test]
    fn encrypted_datagram_replay_window_accepts_late_packets() {
        tinc_test_support::assert_can_create_netns();
        let key = key(5);
        let mut sender = SptpsDatagramCodec::with_keys(key.clone(), key.clone(), 16);
        let mut receiver = SptpsDatagramCodec::with_keys(key.clone(), key, 16);

        let first = sender.encode(1, b"first").unwrap();
        let second = sender.encode(1, b"second").unwrap();
        let third = sender.encode(1, b"third").unwrap();

        assert_eq!(
            SptpsRecord::new(0, 1, b"first"),
            receiver.decode(&first).unwrap()
        );
        assert_eq!(
            SptpsRecord::new(2, 1, b"third"),
            receiver.decode(&third).unwrap()
        );
        assert_eq!(
            SptpsRecord::new(1, 1, b"second"),
            receiver.decode(&second).unwrap()
        );
        assert!(matches!(
            receiver.decode(&second),
            Err(SptpsError::Replay { seqno: 1, .. })
        ));
    }

    #[test]
    fn encrypted_datagram_replay_window_handles_far_future_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut replay = SptpsReplayWindow::new(4);
        replay.accept(0).unwrap();

        assert!(matches!(
            replay.accept(40),
            Err(SptpsError::FarFuture {
                seqno: 40,
                expected_seqno: 1,
                distance: 39,
                count: 1,
            })
        ));
        assert_eq!(1, replay.expected_seqno());

        replay.accept(40).unwrap();
        assert_eq!(41, replay.expected_seqno());
        assert_eq!(2, replay.received());
    }
}

use thiserror::Error;

use crate::vault::SecretKind;

/// Result alias used throughout the core.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Every failure the core can report to a host.
///
/// Decryption failures are deliberately coarse: an attacker must not learn
/// *why* a ciphertext was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("invalid folder path {0:?}: {1}")]
    InvalidPath(String, &'static str),

    #[error("invalid tag {0:?}: {1}")]
    InvalidTag(String, &'static str),

    #[error("invalid username {0:?}: {1}")]
    InvalidUsername(String, &'static str),

    #[error("wrong password or corrupted account record")]
    Unlock,

    #[error("decryption failed: wrong key or tampered data")]
    Decrypt,

    #[error("not signed")]
    Unsigned,

    #[error("signature does not verify for the expected signer")]
    BadSignature,

    #[error("grant is addressed to a different account")]
    NotRecipient,

    #[error("password hashing parameters are weaker than the minimum ({0})")]
    WeakKdf(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("metadata kind {meta:?} does not match body kind {body:?}")]
    KindMismatch { meta: SecretKind, body: SecretKind },

    #[error("encoding failed: {0}")]
    Encode(String),

    #[error("decoding failed: {0}")]
    Decode(String),

    #[error("unsupported format version {0}")]
    UnsupportedFormat(u8),
}

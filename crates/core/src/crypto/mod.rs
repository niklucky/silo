//! Key hierarchy and primitives.
//!
//! ```text
//! password + salt ───Argon2id───▶ master key
//! master key ───HKDF("account-key-wrap")───▶ account wrapping key
//! account wrapping key ───XChaCha20-Poly1305───▶ wraps the account X25519 secret key
//!
//! per secret revision:   random data key
//! data key ───XChaCha20-Poly1305───▶ meta ciphertext, body ciphertext
//! data key ───X25519 + HKDF + XChaCha20-Poly1305───▶ wrapped for each grantee (a grant)
//! ```
//!
//! The account keypair is random, not derived from the password, so changing the
//! password re-wraps one 32-byte key instead of re-encrypting the vault.
//!
//! Every ciphertext is bound to its context through associated data (secret id,
//! revision, part, recipient), so blobs cannot be swapped between secrets or
//! grants re-pointed at another account.
//!
//! Randomness is always supplied by the host through [`CryptoRng`]. Only vetted
//! RustCrypto primitives are used; nothing here is a custom construction beyond
//! the standard ECIES-style key wrap in [`WrappedKey`].
//!
//! Known gap: grants are not signed, so a recipient cannot yet prove *who* shared
//! a secret with them. Signing arrives together with the sync layer.

mod aead;
pub(crate) mod bytes;
mod kdf;
mod keys;
mod wrap;

pub use aead::{Ciphertext, Nonce};
pub use kdf::{KdfParams, MasterKey};
pub use keys::{DataKey, Fingerprint, KEY_LEN, PublicKey, SecretKey};
pub use rand_core::CryptoRng;
pub use wrap::WrappedKey;

pub(crate) use aead::{open, seal};

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
//!
//! account X25519 secret key ───HKDF("signing-key")───▶ account Ed25519 signing key
//! signing key ───Ed25519───▶ signs each revision and each grant
//! master key ───HKDF("server-auth")───▶ server login key (proves the password to a sync server)
//! ```
//!
//! The account keypair is random, not derived from the password, so changing the
//! password re-wraps one 32-byte key instead of re-encrypting the vault.
//!
//! Every ciphertext is bound to its context through associated data (secret id,
//! revision, part, recipient), so blobs cannot be swapped between secrets or
//! grants re-pointed at another account.
//!
//! Domain-separation strings (`b"secret/v1/..."`) predate the rename to Silo and
//! stay as they are: they are part of the ciphertext format, and changing them
//! would make every existing vault unreadable.
//!
//! Randomness is always supplied by the host through [`CryptoRng`]. Only vetted
//! RustCrypto primitives are used; nothing here is a custom construction beyond
//! the standard ECIES-style key wrap in [`WrappedKey`].
//!
//! Signatures make authorship checkable. Anyone who knows an account's public
//! key can seal a revision and grant it to that account, a sync server
//! included, so a host only trusts revisions and grants signed by a key it
//! already knows: its own account's, or later a verified contact's.
//!
//! Newer domain strings start with `b"silo/v1/..."`; the older ones above keep
//! their `secret/` prefix.

mod aead;
pub(crate) mod bytes;
mod kdf;
mod keys;
mod sign;
mod wrap;

pub use aead::{Ciphertext, Nonce};
pub use kdf::{AuthKey, KdfAlgorithm, KdfParams, MasterKey};
pub use keys::{DataKey, Fingerprint, KEY_LEN, PublicKey, SecretKey};
pub use rand_core::CryptoRng;
pub use sign::{SIGNATURE_LEN, Signature, SigningPublicKey};
pub use wrap::WrappedKey;

pub(crate) use aead::{open, seal};
pub(crate) use sign::SigningKey;

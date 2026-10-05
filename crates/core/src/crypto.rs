//! Key hierarchy and primitives.
//!
//! Planned shape, to be implemented in the next step:
//!
//! - Master password → Argon2id → account key.
//! - Account keypair: X25519 for wrapping data keys, Ed25519 for signing.
//! - Each secret has a random data key; the payload is sealed with XChaCha20-Poly1305.
//! - Sharing wraps the data key to each grantee's public key. Revoking deletes the
//!   grant and rotates the data key for the next version.
//!
//! Only vetted primitives (RustCrypto / libsodium-compatible) are used here.
//! Randomness is injected by the host, never pulled from a global source.

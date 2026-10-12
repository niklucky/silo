//! `silo-core`: the platform-independent heart of Silo.
//!
//! Rules for this crate:
//!
//! - **No platform IO.** No filesystem, network, clock or randomness source of its
//!   own. Hosts (CLI, server, desktop, extension) supply bytes in and get bytes out.
//!   Randomness arrives as a [`crypto::CryptoRng`], timestamps as plain integers.
//! - **Compiles unchanged** for native targets and `wasm32-unknown-unknown`.
//! - **Stable contract.** Everything `pub` here is consumed by the hosts and mirrored
//!   into TypeScript bindings; breaking changes must regenerate those bindings.
//!
//! Start with [`account`] for unlocking, then [`vault`] for sealing secrets and
//! granting access. [`crypto`] documents the key hierarchy.

pub mod account;
pub mod crypto;
pub mod error;
pub mod sync;
pub mod vault;

pub use account::{AccountKeys, AccountRecord};
pub use error::{Error, Result};

/// Semantic version of the core crate, baked in at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the core crate version.
///
/// Every host calls this first; it is the end-to-end smoke test for the
/// Rust-to-host bridge (Tauri command, wasm-bindgen export, CLI subcommand).
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
pub(crate) mod testing {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::crypto::KdfParams;

    /// Deterministic RNG for tests. Never use outside tests.
    pub fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// Argon2 parameters that are fast enough for a test suite and useless for security.
    pub fn weak_kdf(rng: &mut ChaCha20Rng) -> KdfParams {
        KdfParams::new(rng, 256, 1, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}

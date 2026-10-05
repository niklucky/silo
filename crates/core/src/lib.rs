//! `secret-core`: the platform-independent heart of Secret.
//!
//! Rules for this crate:
//!
//! - **No platform IO.** No filesystem, network, clock or randomness source of its
//!   own. Hosts (CLI, server, desktop, extension) supply bytes in and get bytes out.
//! - **Compiles unchanged** for native targets and `wasm32-unknown-unknown`.
//! - **Stable contract.** Everything `pub` here is consumed by the hosts and mirrored
//!   into TypeScript bindings; breaking changes must regenerate those bindings.

pub mod crypto;
pub mod sync;
pub mod vault;

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
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}

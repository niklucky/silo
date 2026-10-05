//! wasm-bindgen surface over `secret-core` for the browser extension.
//!
//! Build with `scripts/build-wasm.sh`; output lands in `packages/bindings/wasm`.

use wasm_bindgen::prelude::*;

/// Core crate version. First round-trip smoke test from the extension.
#[wasm_bindgen]
pub fn version() -> String {
    secret_core::version().to_owned()
}

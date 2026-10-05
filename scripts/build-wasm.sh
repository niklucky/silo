#!/usr/bin/env sh
# Builds crates/wasm for the browser and emits JS/TS glue into packages/bindings/wasm.
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching Cargo.toml.
set -eu
cd "$(dirname "$0")/.."

cargo build -p secret-wasm --target wasm32-unknown-unknown --release

wasm-bindgen \
  --target web \
  --out-dir packages/bindings/wasm \
  --out-name secret_wasm \
  target/wasm32-unknown-unknown/release/secret_wasm.wasm

echo "wasm bindings written to packages/bindings/wasm"

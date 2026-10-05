# Secret

Self-hosted secrets manager for people and projects. Website logins, bank cards,
environment variables and secret files, with nested folders, tags, sharing you can
revoke, and HTTP Basic Auth autofill in the browser.

One Rust core, several hosts: CLI, sync server, desktop app, browser extension,
later mobile.

## Layout

```
Cargo.toml                 Cargo workspace (resolver 3, edition 2024)
crates/
  core/                    secret-core: crypto, vault model, sync protocol. No platform IO.
  cli/                     secret: clap binary
  server/                  secret-server: axum + SQLite (SQLite not wired yet)
  wasm/                    secret-wasm: wasm-bindgen surface over core for the extension
apps/
  desktop/                 Tauri 2 + React + Vite; src-tauri/ is a workspace member
  extension/               WXT + React; Chrome, Firefox/Zen and Safari builds
packages/
  ui/                      @secret/ui: shared React components
  bindings/                @secret/bindings: generated TS types (tauri-specta, wasm-bindgen)
scripts/
  build-wasm.sh            cargo build --target wasm32 + wasm-bindgen → packages/bindings/wasm
```

The core crate is the only place that touches keys or plaintext. Hosts supply
storage and transport and get bytes back. It compiles unchanged for native,
`wasm32-unknown-unknown` and, later, mobile via UniFFI.

## Prerequisites

- Rust stable via rustup. `rust-toolchain.toml` adds clippy, rustfmt and the wasm target.
- `cargo install wasm-bindgen-cli` at the version pinned in `Cargo.toml` (`wasm-bindgen = "=0.2.x"`).
- Node 20+ and pnpm 9.
- Tauri 2 platform prerequisites: Xcode Command Line Tools on macOS; see
  https://tauri.app/start/prerequisites/ for Linux packages.

The Tauri CLI refuses to build if the `tauri` crate and `@tauri-apps/api` differ in
minor version. When bumping one, bump the other. Cargo picks the newest crate the
workspace `rust-version` allows, so a stale-looking `tauri` in `Cargo.lock` usually
means that field needs raising.

## Commands

| Task                                   | Command                                   |
| -------------------------------------- | ----------------------------------------- |
| Build and test native crates           | `cargo build` · `cargo test`              |
| Run the CLI                            | `cargo run -p secret-cli -- version`      |
| Run the server                         | `cargo run -p secret-server` then `curl localhost:8787/health` |
| Build WASM + JS glue                   | `pnpm build:wasm`                         |
| Regenerate desktop TS bindings         | `pnpm bindings:desktop`                   |
| Desktop app, dev mode                  | `pnpm dev:desktop`                        |
| Extension, dev mode (Chrome)           | `pnpm dev:extension`                      |
| Extension, dev mode (Firefox / Zen)    | `pnpm --filter @secret/extension dev:firefox` |
| Extension, production build            | `pnpm build:extension`                    |
| Type-check all TS packages             | `pnpm typecheck`                          |

`cargo build` at the root builds core, cli and server only. The wasm crate is built
by `pnpm build:wasm`; the desktop crate by the Tauri CLI.

## How the bridges work

- **Desktop.** Tauri commands in `apps/desktop/src-tauri/src/lib.rs` are registered
  once in `specta_builder()`. The `export_bindings` test writes
  `packages/bindings/src/desktop.ts`, which the React app imports as `commands.*`.
  Run `pnpm bindings:desktop` after changing a command; commit the result.
- **Extension.** `crates/wasm` exports functions with `#[wasm_bindgen]`.
  `scripts/build-wasm.sh` emits `packages/bindings/wasm/`, which is gitignored.
  `apps/extension/lib/core.ts` loads it once per JS context.

## Status

Scaffold. Every host round-trips `secret_core::version()` and nothing more.
The `crypto`, `vault` and `sync` modules document their intended shape and are empty.

Next steps, in order:

1. Core: key hierarchy, secret and folder model, encrypted blob format, tests.
2. CLI: init, add, get, `secret run -- cmd` env injection, dotenv export, file pull.
3. Server: SQLite schema for blobs and grants, auth, push/pull.
4. Extension: Basic Auth via declarativeNetRequest session rules and `onAuthRequired`.
5. Sharing as grants with wrapped data keys; revoke rotates the key.
6. Desktop UI, then login and card autofill, then mobile.

Hardening still to do: set a real CSP in `tauri.conf.json` (currently `null`, the
template default), pick a license, and write the threat model.

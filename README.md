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
  agent/                   secret-agent: on-disk store, unlock session, Unix-socket protocol, client
  cli/                     secret: thin client over the agent (clap)
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

`cargo build` at the root builds core, agent, cli and server only. The wasm crate is
built by `pnpm build:wasm`; the desktop crate by the Tauri CLI.

## Using the CLI

```sh
secret init                                   # create ~/.secret, unlock
secret add env projects/api/dev-env DB_URL=postgres://localhost/api API_KEY=sk-test
secret add env projects/api/prod-env --from-file .env.prod
secret add login work/github --username me --url https://github.com --tag dev
secret add file projects/api/deploy-key ./id_ed25519
echo "pin 1234" | secret add note personal/bank --tag money

secret ls                                     # everything, as a table
secret ls projects/api --kind env             # filter by folder, kind, --tag
secret get work/github                        # id, folder/title path, or a unique title
secret get work/github --field password       # one value, for piping
secret run projects/api/dev-env -- npm start  # inject env vars, exec the command
secret export dev-env > .env                  # dotenv; also --format shell|json
secret file pull deploy-key -o ./id_ed25519

secret lock | secret unlock --ttl 8h | secret status | secret agent stop
```

The first `secret unlock` (or `secret init`) starts `secret agent run` detached in its
own session. The agent holds the unlocked keys in memory, auto-locks after the TTL
(default 12h), and serves every other command over `~/.secret/agent.sock`. Clients
never see a key; they receive decrypted secrets over the socket, which file
permissions restrict to your user.

| Variable              | Purpose                                              |
| --------------------- | ---------------------------------------------------- |
| `SECRET_HOME`         | Data directory (default `~/.secret`)                 |
| `SECRET_AGENT_SOCKET` | Socket path (default `$SECRET_HOME/agent.sock`)      |
| `SECRET_PASSWORD`     | Skip the password prompt; for scripts and CI only    |

Unix only for now (sockets, file modes). Windows needs named pipes; later.

## How the bridges work

- **Desktop.** Tauri commands in `apps/desktop/src-tauri/src/lib.rs` are registered
  once in `specta_builder()`. The `export_bindings` test writes
  `packages/bindings/src/desktop.ts`, which the React app imports as `commands.*`.
  Run `pnpm bindings:desktop` after changing a command; commit the result.
- **Extension.** `crates/wasm` exports functions with `#[wasm_bindgen]`.
  `scripts/build-wasm.sh` emits `packages/bindings/wasm/`, which is gitignored.
  `apps/extension/lib/core.ts` loads it once per JS context.

## Status

Core and agent are implemented and tested; the CLI is usable for local, single-user
work. Desktop and extension still only round-trip `secret_core::version()`.

- **`secret-core`.** Accounts (Argon2id, X25519 keypair wrapped under a derived
  key), sealed secrets (fresh data key per revision, metadata and body sealed
  separately with XChaCha20-Poly1305, CBOR inside), grants (data key wrapped to a
  recipient public key). Every ciphertext is bound to its context through associated
  data. No IO; builds for `wasm32`.
- **`secret-agent`.** `~/.secret` layout with 0700/0600 permissions and atomic
  writes. `Session` opens every readable secret's metadata on unlock and bodies on
  demand. Line-delimited JSON protocol over a Unix socket with `status`, `unlock`,
  `lock`, `shutdown`, `list`, `get`, `add`, `remove`. Selector resolution by id,
  `folder/title` path, or unique title. Client with detached spawn.
- **`secret`.** init, unlock, lock, status, agent run/stop, ls, add
  login/env/file/note, get, rm, run, export, file pull.

Known gaps:

- Grants are not signed, so a recipient cannot prove who shared with them.
  Documented in `crypto/mod.rs`; lands with the sync layer.
- No `update` yet: changing a secret means remove and add. Revisions exist in the
  format; the agent protocol just has no method for them.
- The agent does not verify the peer's uid on the socket; it relies on file modes.
- Killing the agent leaves a stale socket; the next `unlock` cleans it up.

Next steps, in order:

1. Agent: `update` with revisions, card kind on the CLI.
2. Server: SQLite schema for blobs and grants, auth, push/pull; agent sync.
3. Extension: Basic Auth via declarativeNetRequest session rules and `onAuthRequired`,
   talking to the agent through a native-messaging bridge.
4. Sharing end to end with invites and fingerprint verification; signed grants.
5. Desktop UI over the agent, then login and card autofill, then mobile.

Hardening still to do: set a real CSP in `tauri.conf.json` (currently `null`, the
template default), pick a license, and write the threat model.

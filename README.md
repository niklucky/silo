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
  cli/                     secret (CLI, clap) and secret-native-host (browser bridge)
  server/                  secret-server: axum + SQLite (SQLite not wired yet)
  wasm/                    secret-wasm: wasm-bindgen surface over core for the extension
apps/
  desktop/                 Tauri 2 + React + Vite; src-tauri/ is a workspace member
  extension/               WXT + React; Firefox/Zen (MV2) and Chrome (MV3) builds
packages/
  ui/                      @secret/ui: shared React components
  bindings/                @secret/bindings: generated TS types (tauri-specta, wasm-bindgen)
scripts/
  build-wasm.sh            cargo build --target wasm32 + wasm-bindgen → packages/bindings/wasm
  basic-auth-server.py     local HTTP Basic Auth playground for testing the extension
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
| Extension, build for Firefox / Zen     | `pnpm --filter @secret/extension build:firefox` → `apps/extension/.output/firefox-mv2` |
| Extension, build for Chrome            | `pnpm build:extension` → `apps/extension/.output/chrome-mv3` |
| Extension, dev mode with live reload   | `pnpm --filter @secret/extension dev:firefox` or `pnpm dev:extension` |
| Basic Auth test server                 | `python3 scripts/basic-auth-server.py` → http://localhost:8099 |
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

secret match https://dev.example.com/admin     # which logins the extension would use
secret lock | secret unlock --ttl 8h | secret status | secret agent stop
secret browser install | secret browser status # connect browsers, see below
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

## Browser extension: HTTP Basic Auth

The extension answers `401` challenges with a saved login so the browser never
shows its password dialog. It holds no keys: it asks the agent, through a
native-messaging bridge, for the best login for the URL being loaded.

```
browser ──native messaging──▶ secret-native-host ──unix socket──▶ secret agent
          (stdio, 4-byte length + JSON)                 (same protocol as the CLI)
```

Setup, once per machine:

```sh
cargo install --path crates/cli --locked   # installs secret and secret-native-host
secret init                                # if you have no account yet
secret browser install                     # writes manifests for every browser found
secret browser status
```

`secret browser install` writes `dev.secret.agent.json` into each browser's
native-messaging directory, naming the absolute path of `secret-native-host` and
the one extension id allowed to start it. Zen reads Firefox's directory
([zen-browser/desktop#10622](https://github.com/zen-browser/desktop/issues/10622)),
so it gets both. Flatpak or Snap browsers need `--browser <name> --dir <path>`.
Reinstalling the CLI to a different path means running `install` again.

Load the extension:

- **Zen / Firefox:** `pnpm --filter @secret/extension build:firefox`, open
  `about:debugging#/runtime/this-firefox`, *Load Temporary Add-on*, pick
  `apps/extension/.output/firefox-mv2/manifest.json`. Temporary add-ons vanish on
  restart; a signed build comes later.
- **Chrome:** `pnpm build:extension`, open `chrome://extensions`, enable Developer
  mode, *Load unpacked*, pick `apps/extension/.output/chrome-mv3`. The manifest
  pins a public key so the id is the same on every machine.

Save a login with the URL pattern the site should match, then visit it:

```sh
secret add login dev/local -u nikita --url http://localhost:8099
python3 scripts/basic-auth-server.py        # then open http://localhost:8099/private
```

Patterns: `host`, `host:port`, `*.example.com`, or a full `https://host/path`
prefix. A bare host matches any scheme, port and path; an explicit scheme pins
scheme and port; a path must match at a segment boundary. The most specific
pattern wins; `secret match <url>` shows the ranking.

Browsers remember Basic Auth credentials they have used until they restart, and
an extension can neither read nor clear that cache. So on Firefox/Zen the
extension never feeds it: a `401` is answered by retrying the request with the
extension's own `Authorization` header, and that header is re-checked with the
agent on every navigation (and every 30 s for background requests). `secret
lock` or `secret rm` therefore takes effect on the next page load: the site
asks again, the icon shows a badge, and the popup unlocks. The popup also lists
recent challenges and what happened to each.

Chrome has no blocking request hooks, so there the extension answers the
browser's own challenge and Chrome keeps the credentials until it restarts. The
same fallback applies on Firefox when the first request to a site is not a GET,
or the challenge is not Basic.

Not yet: Safari (no `onAuthRequired`, needs an app-hosted extension), proxy
authentication, saving a login from the browser, form autofill.

## How the bridges work

- **Desktop.** Tauri commands in `apps/desktop/src-tauri/src/lib.rs` are registered
  once in `specta_builder()`. The `export_bindings` test writes
  `packages/bindings/src/desktop.ts`, which the React app imports as `commands.*`.
  Run `pnpm bindings:desktop` after changing a command; commit the result.
- **Extension.** No Rust in the browser: `apps/extension/lib/agent.ts` opens one
  native-messaging port to `secret-native-host`, which forwards each JSON request
  to the agent socket and refuses `shutdown` and `remove`. `lib/protocol.ts`
  mirrors the agent's wire types by hand. The extension id and host name live in
  both `wxt.config.ts` and `crates/cli/src/browser.rs`; change both or neither.
- **WASM.** `crates/wasm` exports functions with `#[wasm_bindgen]` and
  `scripts/build-wasm.sh` emits `packages/bindings/wasm/` (gitignored). Nothing
  consumes it today; it stays for hosts without an agent.

## Status

Core, agent and CLI are implemented and tested for local, single-user work. The
extension fills HTTP Basic Auth in Firefox/Zen and Chrome. The desktop app still
only round-trips `secret_core::version()`.

- **`secret-core`.** Accounts (Argon2id, X25519 keypair wrapped under a derived
  key), sealed secrets (fresh data key per revision, metadata and body sealed
  separately with XChaCha20-Poly1305, CBOR inside), grants (data key wrapped to a
  recipient public key). Every ciphertext is bound to its context through associated
  data. No IO; builds for `wasm32`.
- **`secret-agent`.** `~/.secret` layout with 0700/0600 permissions and atomic
  writes. `Session` opens every readable secret's metadata on unlock and bodies on
  demand. Line-delimited JSON protocol over a Unix socket with `status`, `unlock`,
  `lock`, `shutdown`, `list`, `get`, `add`, `remove`, `match`. Selector resolution
  by id, `folder/title` path, or unique title. Client with detached spawn.
- **`secret`.** init, unlock, lock, status, agent run/stop, ls, add
  login/env/file/note, get, rm, run, export, file pull, match, browser
  install/uninstall/status. `secret-native-host` bridges browsers to the agent.
- **Extension.** Firefox: `onHeadersReceived` retries a Basic `401` with an
  injected `Authorization` header, re-validated per navigation, so the browser
  cache stays empty and lock/remove work. Chrome: `onAuthRequired` with
  asyncBlocking. Loop guard per request id, popup with unlock/lock, matches for
  the current tab and a log of recent challenges.

Known gaps:

- Grants are not signed, so a recipient cannot prove who shared with them.
  Documented in `crypto/mod.rs`; lands with the sync layer.
- No `update` yet: changing a secret means remove and add. Revisions exist in the
  format; the agent protocol just has no method for them.
- The agent does not verify the peer's uid on the socket; it relies on file modes.
- Killing the agent leaves a stale socket; the next `unlock` cleans it up.
- The native host forwards passwords typed into the popup to the agent; the
  browser process sees them in transit, as any extension-based unlock would.
- Replies over native messaging are capped at 1 MiB, so `get` of a large file
  secret fails through the bridge (fine for the CLI).

Next steps, in order:

1. Agent: `update` with revisions, card kind on the CLI.
2. Server: SQLite schema for blobs and grants, auth, push/pull; agent sync.
3. Extension: declarativeNetRequest header rules on Chrome; save a login from the
   popup; signed builds.
4. Sharing end to end with invites and fingerprint verification; signed grants.
5. Desktop UI over the agent, then login and card autofill, then mobile.

Hardening still to do: set a real CSP in `tauri.conf.json` (currently `null`, the
template default), pick a license, and write the threat model.

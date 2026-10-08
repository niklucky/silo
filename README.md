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
  login-form-server.py     local login form playground (sign-in, sign-up, change password, iframe)
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
| Login form test server                 | `python3 scripts/login-form-server.py` → http://localhost:8200 |
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
secret match https://dev.example.com --site    # plus logins for example.com, admin.example.com, …
secret history work/github                     # earlier revisions; --revision N shows one
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

When a site challenges and the vault has no login for it, or is locked, the
extension takes the tab to its own sign-in page instead of the browser's dialog.
There you unlock if needed, then enter the username and password once. *Save and
continue* stores them as a login (default `web/<host>`, URL pattern = the site's
origin) and retries the page with the header injected. *Use once* keeps them for
this browser session without storing. *Cancel* hands the site back to the
browser for 15 seconds. Only top-level navigations get this page; frames,
fetches and non-GET requests still fall through to the browser's dialog.
If the username is already saved for another host of the same site, the page
asks first, as described under [Same site, same username](#same-site-same-username).

Chrome has no blocking request hooks, so there the extension answers the
browser's own challenge and Chrome keeps the credentials until it restarts. Its
sign-in page is reached by cancelling the request and navigating the tab, which
flashes an error page briefly. The same fallback applies on Firefox when the
first request to a site is not a GET, or the challenge is not Basic.

Not yet: Safari (no `onAuthRequired`, needs an app-hosted extension), proxy
authentication, editing a saved login from the browser.

## Browser extension: login forms

Focus a username or password field on a site with a matching login and a menu
drops down under it listing those logins (username and `folder/title`). Click one
to fill both fields; the page sees ordinary `input` and `change` events, so
React-style controlled forms pick the values up. The popup's *Fill* button does
the same for the current tab. When the vault is locked the menu offers *Unlock*,
which opens a small extension window for the master password; it is never typed
into the page.

Settings (popup → *Settings*, or the add-on's preferences) choose what focusing
a field does: *Show the menu* (default) or *Show a button*, a small key inside
the field that opens the menu when clicked. The button mode leaves the field's
focus to another password manager such as Apple Passwords, whose menu otherwise
opens in the same place. No extension can hide another extension's menu, so
this is the way to run both.

```sh
secret add login web/playground -u nikita --url localhost:8200
python3 scripts/login-form-server.py        # then open http://localhost:8200
```

What it recognises: a visible password field and the text field before it, or a
lone username field (the first page of a two-step sign-in). Forms with two or
more password fields (sign-up, change password) and fields marked
`autocomplete="new-password"` get no saved logins, only generated passwords.

Generated passwords. On a sign-up or change-password form the password field's
menu offers two suggestions, each with a four-step strength meter and its
entropy: *easy to type* (`Bakomi-tuvela-rosedu7-fanipo`, consonant-vowel
syllables, about 83 bits) and *random* (20 characters without look-alikes,
about 121 bits). On other password fields the menu ends with *Generate
password…*. With the vault unlocked, picking one first saves it as a new
login, `web/<host>` with the username already typed in the form and the site's
origin as URL pattern, and only then fills the new-password and confirmation
fields, so a password the page has seen is never missing from the vault. With
the vault locked or the agent unreachable, generating still works: the menu
says the password will not be saved, and after filling it shows the password
with a *Copy* button until you leave the field. Fields marked
`current-password` never get suggestions. The bit counts are
exact for the generator, computed from its alphabet and structure, not
estimated from the result.

### Saving what you sign in with

When you send a login form with a username and password that Secret does not
have, a small panel in the top-right corner of the page asks *Save login for
`<host>`?*. It appears on the page you land on, or on the same page when the
site signs in without reloading (`fetch`), and stays offered for three minutes.
Nothing is stored until you answer:

- *Save*: a new login `web/<host>` with the page's origin as URL pattern.
- *Update `web/example.com`*: when the site already has a login with that
  username (or one without a username, or, on a change-password form, the one
  whose password is the form's current password). It gets the new password; the
  old one stays in its history. See [Same site, same username](#same-site-same-username).
- *Not now*, or *Never for this site*, which the settings page can undo.
  Settings can also turn the offer off altogether.

A login that already fills on the page with that exact username and password
is not offered again. The two steps of a two-step sign-in are joined: the
username sent on the first page goes with the password sent on the second. When
the vault is locked the panel offers *Unlock Secret* and then asks again. A
form counts as sent on a trusted `submit`, a click on its submit button or on a
button that reads like *Sign in*/*Continue*/*Next*, or Enter in one of its
fields. Secret cannot tell whether the site accepted the password, so a typo
gets offered too; answer *Not now*.

The typed password goes from the content script to the background, which keeps
it in memory only, for the tab that sent it, until you answer, the offer
expires, or the tab closes. The panel never receives it.

### Same site, same username

`dev.example.com` and `example.com` are separate logins: each fills only where
its URL patterns match. Saving never replaces one silently. When a save (a
generated password, or the Basic Auth sign-in page) finds a login with the same
username on the same site, it asks first, and nothing is filled until you answer:

- *Add a new login*: saved next to the existing ones, which stay as they are.
- *Overwrite `web/example.com`*: that login gets the new password, and the
  page's origin is added to its URL patterns if it did not fill there already.
  The agent keeps the replaced revision; `secret history web/example.com` lists
  it and `--revision N` shows it.

"Same site" is the registrable domain from the public suffix list, so
`a.example.co.uk` and `b.example.co.uk` belong together while `alice.github.io`
and `bob.github.io` do not. `localhost` and every `*.localhost` count as one
site; other IP addresses are a site each. A form without a username field
offers every login of the site, for change-password pages that only ask for
passwords.

Safety rules:

- Nothing is filled on page load. A login is filled only after a trusted click
  in the menu or the popup.
- The background answers for the URL of the frame that asked, as the browser
  reports it, and releases a password only for a login whose URL patterns match
  that frame. A page cannot ask for another site's login by id.
- The menu lives in a closed shadow root with inline styles; page scripts cannot
  read it or restyle it, and synthetic clicks are ignored.
- Content scripts can only send seven messages (list logins, fill one, open the
  unlock window, save a generated password, report a sent form, and get or
  answer the tab's save offer); agent calls are reserved for extension pages.
  A save can only overwrite a login the background itself offered for that
  frame's site and username, and only the tab's top frame sees or answers its
  offer.
- On a page that is not HTTPS (localhost excepted) the menu says so before you
  fill.

Not yet: keyboard navigation in the menu and the save panel, fields inside
shadow DOM, TOTP codes, choosing the folder and title when saving.

## How the bridges work

- **Desktop.** Tauri commands in `apps/desktop/src-tauri/src/lib.rs` are registered
  once in `specta_builder()`. The `export_bindings` test writes
  `packages/bindings/src/desktop.ts`, which the React app imports as `commands.*`.
  Run `pnpm bindings:desktop` after changing a command; commit the result.
- **Extension.** No Rust in the browser: `apps/extension/lib/agent.ts` opens one
  native-messaging port to `secret-native-host`, which forwards each JSON request
  to the agent socket and refuses `shutdown`, `remove` and `history`. `lib/protocol.ts`
  mirrors the agent's wire types by hand. The extension id and host name live in
  both `wxt.config.ts` and `crates/cli/src/browser.rs`; change both or neither.
- **WASM.** `crates/wasm` exports functions with `#[wasm_bindgen]` and
  `scripts/build-wasm.sh` emits `packages/bindings/wasm/` (gitignored). Nothing
  consumes it today; it stays for hosts without an agent.

## Status

Core, agent and CLI are implemented and tested for local, single-user work. The
extension fills HTTP Basic Auth and login forms in Firefox/Zen and Chrome. The desktop app still
only round-trips `secret_core::version()`.

- **`secret-core`.** Accounts (Argon2id, X25519 keypair wrapped under a derived
  key), sealed secrets (fresh data key per revision, metadata and body sealed
  separately with XChaCha20-Poly1305, CBOR inside), grants (data key wrapped to a
  recipient public key). Every ciphertext is bound to its context through associated
  data. No IO; builds for `wasm32`.
- **`secret-agent`.** `~/.secret` layout with 0700/0600 permissions and atomic
  writes. `Session` opens every readable secret's metadata on unlock and bodies on
  demand. Line-delimited JSON protocol over a Unix socket with `status`, `unlock`,
  `lock`, `shutdown`, `list`, `get`, `add`, `update`, `remove`, `history`,
  `match` (optionally with same-site logins). `update` re-seals under a fresh
  data key, re-grants every current recipient, refuses a stale base revision,
  and archives the replaced revision under `vault/history/<id>/`. Selector
  resolution by id, `folder/title` path, or unique title. Client with detached
  spawn.
- **`secret`.** init, unlock, lock, status, agent run/stop, ls, add
  login/env/file/note, get, rm, run, export, file pull, history, match, browser
  install/uninstall/status. `secret-native-host` bridges browsers to the agent.
- **Extension.** Firefox: `onHeadersReceived` retries a Basic `401` with an
  injected `Authorization` header, re-validated per navigation, so the browser
  cache stays empty and lock/remove work. Chrome: `onAuthRequired` with
  asyncBlocking. Unknown or locked sites go to the extension's own sign-in page
  (`entrypoints/auth`), which unlocks, saves a login through the agent and
  retries. Loop guard per request id, popup with unlock/lock, matches for the
  current tab and a log of recent activity. Login forms: a content script
  (`entrypoints/login.content.ts`, heuristics in `lib/forms.ts`) shows a menu
  of matching logins and fills on click, or generated passwords
  (`lib/generate.ts`) that are saved before they are filled; sent login forms
  get a save offer (`lib/save-prompt.ts`); the unlock window
  is `entrypoints/unlock`, settings are `entrypoints/options` over
  `storage.local` (`lib/settings.ts`), and the in-field button is
  `lib/field-button.ts`.

Known gaps:

- Grants are not signed, so a recipient cannot prove who shared with them.
  Documented in `crypto/mod.rs`; lands with the sync layer.
- `update` has no CLI command yet (the extension uses it to overwrite logins),
  and history cannot be restored with one command: copy the old values back.
- The agent does not verify the peer's uid on the socket; it relies on file modes.
- Killing the agent leaves a stale socket; the next `unlock` cleans it up.
- The native host forwards passwords typed into the popup to the agent; the
  browser process sees them in transit, as any extension-based unlock would.
- Replies over native messaging are capped at 1 MiB, so `get` of a large file
  secret fails through the bridge (fine for the CLI).

Next steps, in order:

1. Agent: `update` with revisions, card kind on the CLI.
2. Server: SQLite schema for blobs and grants, auth, push/pull; agent sync.
3. Extension: declarativeNetRequest header rules on Chrome; save logins on form
   submit; Safari; signed builds.
4. Sharing end to end with invites and fingerprint verification; signed grants.
5. Desktop UI over the agent, then login and card autofill, then mobile.

Hardening still to do: set a real CSP in `tauri.conf.json` (currently `null`, the
template default), pick a license, and write the threat model.

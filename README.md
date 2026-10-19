# Silo

Self-hosted secrets manager for people and projects. Website logins, bank cards,
environment variables and secret files, with nested folders, tags, sharing you can
revoke, and HTTP Basic Auth autofill in the browser.

One Rust core, several hosts: CLI, sync server, desktop app, browser extension,
later mobile.

## Layout

```
Cargo.toml                 Cargo workspace (resolver 3, edition 2024)
crates/
  core/                    silo-core: crypto, vault model, sync protocol. No platform IO.
  agent/                   silo-agent: on-disk store, unlock session, Unix-socket protocol, client
  cli/                     silo (CLI, clap) and silo-native-host (browser bridge)
  server/                  silo-server: sync server, axum + SQLite
  wasm/                    silo-wasm: wasm-bindgen surface over core for the extension
apps/
  desktop/                 Tauri 2 + React + Vite; src-tauri/ is a workspace member
  extension/               WXT + React; Firefox/Zen (MV2), Chrome (MV3) and Safari (MV2) builds
  safari/                  Xcode project wrapping the Safari build, with the Swift bridge to the agent
packages/
  ui/                      @silo/ui: shared React components
  bindings/                @silo/bindings: generated TS types (tauri-specta, wasm-bindgen)
scripts/
  build-wasm.sh            cargo build --target wasm32 + wasm-bindgen → packages/bindings/wasm
  build-safari.sh          Safari build + xcodebuild → apps/safari/build/Silo for Safari.app
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
- Full Xcode for the Safari extension only.

The Tauri CLI refuses to build if the `tauri` crate and `@tauri-apps/api` differ in
minor version. When bumping one, bump the other. Cargo picks the newest crate the
workspace `rust-version` allows, so a stale-looking `tauri` in `Cargo.lock` usually
means that field needs raising.

## Commands

| Task                                   | Command                                   |
| -------------------------------------- | ----------------------------------------- |
| Build and test native crates           | `cargo build` · `cargo test`              |
| Run the CLI                            | `cargo run -p silo-cli -- version`      |
| Run the sync server                    | `cargo run -p silo-server` then `curl localhost:8787/health` |
| Create an account invite               | `cargo run -p silo-server -- invite`      |
| Build WASM + JS glue                   | `pnpm build:wasm`                         |
| Regenerate desktop TS bindings         | `pnpm bindings:desktop`                   |
| Desktop app, dev mode                  | `pnpm dev:desktop`                        |
| Extension, build for Firefox / Zen     | `pnpm --filter @silo/extension build:firefox` → `apps/extension/.output/firefox-mv2` |
| Extension, build for Chrome            | `pnpm build:extension` → `apps/extension/.output/chrome-mv3` |
| Extension, build for Safari            | `pnpm build:safari` → `apps/safari/build/Silo for Safari.app` |
| Extension, dev mode with live reload   | `pnpm --filter @silo/extension dev:firefox` or `pnpm dev:extension` |
| Basic Auth test server                 | `python3 scripts/basic-auth-server.py` → http://localhost:8099 |
| Login form test server                 | `python3 scripts/login-form-server.py` → http://localhost:8200 |
| Type-check all TS packages             | `pnpm typecheck`                          |

`cargo build` at the root builds core, agent, cli and server only. The wasm crate is
built by `pnpm build:wasm`; the desktop crate by the Tauri CLI.

## Using the CLI

```sh
silo init                                     # set up ~/.silo, optionally with sync, unlock
silo add env projects/api/dev-env DB_URL=postgres://localhost/api API_KEY=sk-test
silo add env projects/api/prod-env --from-file .env.prod
silo add login work/github --username me --url https://github.com --tag dev
silo add file projects/api/deploy-key ./id_ed25519
echo "pin 1234" | silo add note personal/bank --tag money

silo ls                                       # everything, as a table
silo ls projects/api --kind env               # filter by folder, kind, --tag
silo get work/github                          # id, folder/title path, or a unique title
silo get work/github --field password         # one value, for piping
silo run projects/api/dev-env -- npm start    # inject env vars, exec the command
silo export dev-env > .env                    # dotenv; also --format shell|json
silo file pull deploy-key -o ./id_ed25519

silo edit work/github                         # asks field by field; Enter keeps a value
silo edit work/github -p                      # new password, prompted twice; -g generates one
silo edit work/github --add-url gist.github.com --rm-tag dev --path personal/github
silo edit projects/api/dev-env API_KEY=sk-new --unset OLD_KEY

silo match https://dev.example.com/admin      # which logins the extension would use
silo match https://dev.example.com --site     # plus logins for example.com, admin.example.com, …
silo history work/github                      # earlier revisions; --revision N shows one
silo restore work/github                      # undo the last change; --revision N for an older one
silo import ~/Desktop/Passwords.csv -n        # preview an import; drop -n to run it
silo lock | silo unlock --ttl 8h | silo status | silo agent stop
silo browser install | silo browser status    # connect browsers, see below
```

Interactive `silo init` first asks for a sync server URL; Enter skips sync and
creates a local vault. With a server, it asks for a username and an invite code:
an invite creates and registers a new account; Enter at the invite prompt logs
in to an existing account with its master password and downloads its vault.
The same setup can be supplied with flags:

```sh
silo init --server https://silo.example.com -u nikita --invite CODE # new account
silo init --server https://silo.example.com -u nikita               # existing account
```

Registration asks for a new master password only once (with confirmation).
If registration is refused, the local vault stays; retry with `silo sync register`.
Without a terminal on stdin, `silo init` skips the optional sync questions unless
`--server` is supplied, so existing scripts can still create a local vault.

The first `silo unlock` (or `silo init`) starts `silo agent run` detached in its
own session. The agent holds the unlocked keys in memory, auto-locks after the TTL
(default 12h), and serves every other command over `~/.silo/agent.sock`. Clients
never see a key; they receive decrypted secrets over the socket, which file
permissions restrict to your user.

| Variable              | Purpose                                              |
| --------------------- | ---------------------------------------------------- |
| `SILO_HOME`         | Data directory (default `~/.silo`)                 |
| `SILO_AGENT_SOCKET` | Socket path (default `$SILO_HOME/agent.sock`)      |
| `SILO_PASSWORD`     | Skip the master password prompt; for scripts and CI only |
| `SILO_SERVER`       | Default server URL for sync register and login      |

With sync set up, `$SILO_HOME/sync.json` (mode 0600) holds the server address,
the device token and sync progress. `silo sync logout` keeps the progress in
`sync-baseline.json`, so after logging in again to the same account, edits and
deletions made in between still sync as yours.

Unix only for now (sockets, file modes). Windows needs named pipes; later.

### Importing

`silo import FILE` reads a CSV export from Apple Passwords (Passwords → File →
Export All Passwords), Chrome, Firefox or Bitwarden; columns are found by name.
Each login goes where the extension would save it: `web/<host>` (`<host> (2)`
when taken), filling on the site's origin, with notes and TOTP kept. Logins
the vault already has for that site and username are left alone: the same
password is reported as already saved, another password is listed, and
`--replace` updates it (the old one stays in history). Running an import twice
adds nothing. `--dry-run` shows the plan, `--folder` and `--tag` place the new
logins. Rows without a password are skipped. Delete the CSV afterwards: it holds
every password in plain text.

## Sync

A `silo-server` keeps the vaults of its accounts in step across devices. It
stores sealed revisions and never sees a key, a password or a plaintext secret.

```sh
# on the server
silo-server invite                  # one-time code for one account, valid 7 days
silo-server                         # serves on 127.0.0.1:8787 (--db, SILO_SERVER_ADDR)

# the device that has the vault
silo sync register --server https://silo.example.com -u nikita --invite k3f9q-2xw7m-p4hzc-8vd1n
# every other device; on a new machine this creates the vault from the server
silo sync login --server https://silo.example.com -u nikita
silo status                         # same fingerprint on every device

silo sync                           # sync now
silo sync status                    # last sync, changes waiting, errors
silo sync devices                   # this account's devices; --revoke ID locks one out
silo sync logout                    # revoke this device and stop syncing; the vault stays
```

For register and login, the server URL comes from `--server URL`, then
`SILO_SERVER`, then the last server saved in `sync-baseline.json` by logout.
If none is available, the CLI prompts for it. A positional URL is also accepted
for compatibility with existing commands. After logout, `silo sync login -u nikita`
therefore reconnects to the previous server without asking for its address.

While unlocked, the agent syncs on unlock, two seconds after each change, and
every five minutes. Plain `http://` is accepted for `localhost` only; anything
else needs HTTPS, which a proxy in front of the server provides.

What makes it safe to sync through a server you may not fully trust:

- The password never leaves the device. Login sends a key derived from it with
  HKDF, separate from the key that opens the account, and the client refuses
  password hashing settings weaker than its own minimum, so a server cannot
  ask for a cheap hash.
- Every revision, grant and deletion is signed with the account's Ed25519 key.
  A device accepts only what its own account signed; anything else the server
  hands out is ignored and counted in `silo sync` output. A revision older than
  one the device has already seen is ignored too.
- The server knows usernames, device names, how many secrets an account has,
  their sizes and when they change. Nothing else.

Changes made on two devices before they sync are kept, never overwritten. When
both changed the same secret, the newer edit becomes current and the other one
stays in history on every device (`silo history`). An edit also beats a
deletion: deleting on one device while editing on another keeps the edited
secret. `silo sync` lists every such conflict and which side won.

A device's history covers what it has seen since it joined; revisions made on
other devices in between are fetched to fill the gaps.

## Browser extension: HTTP Basic Auth

The extension answers `401` challenges with a saved login so the browser never
shows its password dialog. It holds no keys: it asks the agent, through a
native-messaging bridge, for the best login for the URL being loaded.

When nothing is saved for a host, the extension's sign-in page also lists logins
saved for other hosts of the same site. Picking one adds this host to that
login, so one entry serves `admin.dev.example.com`, `test.dev.example.com` and
so on, and a new password only has to be saved once. If the login already
covers two sibling hosts, you can widen it to `https://*.dev.example.com`
instead; a wildcard never reaches past the site's registrable domain, as the
agent's public suffix list has it. If the site refuses the login you picked on
that page, the link is undone.

```
browser ──native messaging──▶ silo-native-host ──unix socket──▶ silo agent
          (stdio, 4-byte length + JSON)                 (same protocol as the CLI)
```

Setup, once per machine:

```sh
cargo install --path crates/cli --locked   # installs silo and silo-native-host
silo init                                  # if you have no account yet
silo browser install                       # writes manifests for every browser found
silo browser status
```

`silo browser install` writes `dev.silo.agent.json` into each browser's
native-messaging directory, naming the absolute path of `silo-native-host` and
the one extension id allowed to start it. Zen reads Firefox's directory
([zen-browser/desktop#10622](https://github.com/zen-browser/desktop/issues/10622)),
so it gets both. Flatpak or Snap browsers need `--browser <name> --dir <path>`.
Reinstalling the CLI to a different path means running `install` again.

Load the extension:

- **Zen / Firefox:** `pnpm --filter @silo/extension build:firefox`, open
  `about:debugging#/runtime/this-firefox`, *Load Temporary Add-on*, pick
  `apps/extension/.output/firefox-mv2/manifest.json`. Temporary add-ons vanish on
  restart; a signed build comes later.
- **Chrome:** `pnpm build:extension`, open `chrome://extensions`, enable Developer
  mode, *Load unpacked*, pick `apps/extension/.output/chrome-mv3`. The manifest
  pins a public key so the id is the same on every machine.
- **Safari:** `pnpm build:safari` builds the extension, wraps it in
  `apps/safari/build/Silo for Safari.app` and opens the app once so Safari
  registers it; close the window, but leave the app where it is. The build is
  signed ad hoc, so turn on Settings → Advanced → *Show features for web
  developers*, then Develop → Developer Settings → *Allow unsigned extensions*
  (Safari turns it off when it quits). Enable **Silo** under Settings →
  Extensions and allow it on every website. `silo browser install` is not
  needed: Safari reaches the agent through the app (see
  [How the bridges work](#how-the-bridges-work)). To sign with your own
  certificate, set `SILO_SAFARI_IDENTITY` and `SILO_SAFARI_TEAM`.

Save a login with the URL pattern the site should match, then visit it:

```sh
silo add login dev/local -u nikita --url http://localhost:8099
python3 scripts/basic-auth-server.py        # then open http://localhost:8099/private
```

Patterns: `host`, `host:port`, `*.example.com`, or a full `https://host/path`
prefix. A bare host matches any scheme, port and path; an explicit scheme pins
scheme and port; a path must match at a segment boundary. The most specific
pattern wins; `silo match <url>` shows the ranking.

A site can have several logins: the app's own accounts and the one Basic Auth
gate in front of them. Logins marked as Basic Auth answer the `401` first, and
go last in the login-form menu. The extension marks a login itself when it gets
through a challenge or is saved from the sign-in page below; by hand:
`silo add login ... --basic-auth`, or `silo edit web/example.com --basic-auth`
(`--no-basic-auth` to undo). `silo get` and `silo match` show the mark. When the
site refuses a login, the extension tries the next one (at most three), then
shows its sign-in page naming the refused logins. Refusals are forgotten when
the vault locks or the login's password changes.

Browsers remember Basic Auth credentials they have used until they restart, and
an extension can neither read nor clear that cache. So the extension never
feeds it: a `401` is answered by retrying the request with the extension's own
`Authorization` header, and that header is re-checked with the agent on every
navigation (and every 30 s for background requests). `silo lock` or `silo
rm` therefore takes effect on the next page load: the site asks again, the icon
shows a badge, and the popup unlocks. The popup also lists recent challenges and
what happened to each.

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

Chrome has no blocking request hooks, so the header comes from a
`declarativeNetRequest` session rule per origin instead. The first `401` of a
page load adds the rule and loads the page again; the sign-in page is reached
the same way. The check with the agent cannot hold a request there, so after
`silo rm` one more page loads with the old header before the tab moves to the
sign-in page. A lock from the popup removes the rules at once; a lock from the
CLI or the agent's timeout is noticed within 5 seconds. Session rules end with
the browser, like its own cache. Where a page cannot simply be loaded again (a
frame, a fetch, a POST), Chrome gets the credentials the old way and keeps them
until it restarts; Firefox takes the same fallback when the first request to a
site is not a GET, or the challenge is not Basic.

Safari has no `onAuthRequired` at all, so its own dialog opens on a `401`. The
extension sees the response in a non-blocking `onHeadersReceived` and does what
Chrome does: a session rule and the page loaded again, which closes the dialog,
or the sign-in page. Lock and `silo rm` behave as on Chrome. Frames, fetches
and POSTs keep Safari's dialog.

Not yet: proxy authentication, editing a saved login from the browser.

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
silo add login web/playground -u nikita --url localhost:8200
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

When you send a login form with a username and password that Silo does not
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
the vault is locked the panel offers *Unlock Silo* and then asks again. A
form counts as sent on a trusted `submit`, a click on its submit button or on a
button that reads like *Sign in*/*Continue*/*Next*, or Enter in one of its
fields. Silo cannot tell whether the site accepted the password, so a typo
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
  The agent keeps the replaced revision; `silo history web/example.com` lists
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
  native-messaging port to `silo-native-host`, which forwards each JSON request
  to the agent socket and refuses `shutdown`, `remove`, `history` and the sync
  setup methods (`sync_register`, `sync_login`, `sync_logout`,
  `sync_revoke_device`). `lib/protocol.ts`
  mirrors the agent's wire types by hand. The extension id and host name live in
  both `wxt.config.ts` and `crates/cli/src/browser.rs`; change both or neither.
- **Safari.** Safari cannot start a native host. `browser.runtime.sendNativeMessage`
  goes to the app extension inside `Silo for Safari.app`
  (`apps/safari/Extension/SafariWebExtensionHandler.swift`), which sends each
  request to `~/.silo/agent.sock` and refuses the same methods. Its
  sandbox allows connecting to that socket and nothing else
  (`Extension.entitlements`). It cannot start the agent; run `silo unlock`
  first. The extension files are copied into the app at build time from
  `apps/extension/.output/safari-mv2`.
- **WASM.** `crates/wasm` exports functions with `#[wasm_bindgen]` and
  `scripts/build-wasm.sh` emits `packages/bindings/wasm/` (gitignored). Nothing
  consumes it today; it stays for hosts without an agent.

## Status

Core, agent and CLI are implemented and tested for local, single-user work. The
extension fills HTTP Basic Auth and login forms in Firefox/Zen, Chrome and Safari.
Sync between devices works through `silo-server`; the server is not deployed
anywhere yet. The desktop app still only round-trips `silo_core::version()`.

- **`silo-core`.** Accounts (Argon2id, X25519 keypair wrapped under a derived
  key), sealed secrets (fresh data key per revision, metadata and body sealed
  separately with XChaCha20-Poly1305, CBOR inside), grants (data key wrapped to a
  recipient public key). Every ciphertext is bound to its context through associated
  data. Each account also has an Ed25519 signing key, derived from its X25519 secret
  key, that signs every new revision and grant; the fingerprint covers both public
  keys. A server login key is derived from the master key for sync, and KDF
  parameters from elsewhere must meet a minimum. No IO; builds for `wasm32`.
- **`silo-agent`.** `~/.silo` layout with 0700/0600 permissions and atomic
  writes. `Session` opens every readable secret's metadata on unlock and bodies on
  demand. Line-delimited JSON protocol over a Unix socket with `status`, `unlock`,
  `lock`, `shutdown`, `list`, `get`, `add`, `update`, `remove`, `history`,
  `match` (optionally with same-site logins), `site` (a URL's registrable
  domain). `update` re-seals under a fresh
  data key, re-grants every current recipient, refuses a stale base revision,
  and archives the replaced revision under `vault/history/<id>/`. Selector
  resolution by id, `folder/title` path, or unique title. Client with detached
  spawn. Sync (`src/sync/`): setup, a blocking `ureq` client, and an engine that
  pulls, resolves conflicts and pushes in rounds without holding the agent's
  lock during network calls; a background thread runs it while unlocked.
- **`silo`.** init, unlock, lock, status, agent run/stop, ls, add
  login/env/file/note, get, edit, restore, import, rm, run, export, file pull, history, match, browser
  install/uninstall/status, sync register/login/status/devices/logout.
  `silo-native-host` bridges browsers to the agent.
- **`silo-server`.** axum over one SQLite file (`--db`, default
  `silo-server.db`; schema versioned with `user_version`). Accounts are created
  with a one-time invite (`silo-server invite`) and a proof that the registrant
  holds both secret keys (an Ed25519 signature and a MAC under an X25519 shared
  secret with the server's static key, `GET /v1/server`), and only with the
  recommended KDF profile, so prelogin cannot tell real accounts from made-up
  ones; login sends the server login key, stored as
  a SHA-256 hash, and returns a revocable device token. Prelogin answers
  unknown usernames with stable made-up KDF parameters; failed logins back off
  per username, in a bounded table that forgets after an hour. Accounts connect to each other mutually (one asks, the other
  accepts) and only then see each other's identity or may grant to each other.
  Push takes revisions on top of the current one (`base_revision`) and signed
  tombstones (a put on a deleted secret must say `restore`, so an edit that
  never saw the deletion conflicts instead of undoing it), checks signatures,
  ownership and grant recipients, and answers
  each item with ok, conflict (with the current state) or rejected. Pull
  returns, by a server-wide change counter, every secret the account holds a
  grant for; owners see all grants, others only their own. Every revision is
  kept. Wire types and endpoints are in `silo_core::sync`.
- **Extension.** Firefox: `onHeadersReceived` retries a Basic `401` with an
  injected `Authorization` header, re-validated per navigation, so the browser
  cache stays empty and lock/remove work. Chrome: `onAuthRequired` with
  asyncBlocking adds a `declarativeNetRequest` session rule that sends the header
  (`lib/header-rules.ts`) and reloads the page; Safari does the same from a
  non-blocking `onHeadersReceived`. Unknown or locked sites go to the extension's own sign-in page
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

- Revisions written before signing existed stay unsigned on disk until sync
  uploads them (it signs them first). The agent does not check signatures of
  its own files; it trusts the local disk.
- A password change has no command yet. The server keeps a versioned account
  record for it, but devices do not fetch a changed record on their own; `silo
  sync logout` and `login` again picks it up.
- Secrets shared by other accounts are ignored on pull until sharing lands.
- The agent does not verify the peer's uid on the socket; it relies on file modes.
- Killing the agent leaves a stale socket; the next `unlock` cleans it up.
- The native host forwards passwords typed into the popup to the agent; the
  browser process sees them in transit, as any extension-based unlock would.
- Replies over native messaging are capped at 1 MiB, so `get` of a large file
  secret fails through the bridge (fine for the CLI).
- The Safari bridge only knows the default socket path; `SILO_HOME` and
  `SILO_AGENT_SOCKET` are not seen inside the sandbox.

Next steps, in order:

1. Card kind on the CLI.
2. Deploying the server: VPS, TLS proxy, backups.
3. Extension: signed builds; the Safari extension inside the desktop app.
4. Sharing end to end: connections and fingerprint checks in the CLI, grants to
   connected accounts, revocation notices.
5. Desktop UI over the agent, then login and card autofill, then mobile.

Hardening still to do: set a real CSP in `tauri.conf.json` (currently `null`, the
template default), pick a license, and write the threat model.

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
deployment/
  Dockerfile               multi-stage silo-server image; non-root runtime
  compose.yaml             production server, loopback port and persistent bind mounts
  .env.example             copy to ignored .env.production for VPS settings
  provision.sh             workstation entry point for shared-host preparation
  provision-host.sh        remote implementation; invoked by provision.sh
  backup.sh                online SQLite snapshots, installed as silo-backup
  github-env.sh            validate and upload production GitHub settings
  deploy-ssh.sh            runner entry point; pinned SSH and temporary registry credentials
  deploy.sh                remote pull, pre-deploy backup, health check and recovery
  nginx/                   only the Silo HTTP/TLS site
  tests/                   isolated Debian provisioning and backup checks
.github/workflows/         PR/main checks and vX.Y.Z server releases
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
silo init                                     # create ~/.silo, unlock
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
silo sync register https://silo.example.com -u nikita --invite k3f9q-2xw7m-p4hzc-8vd1n
# every other device; on a new machine this creates the vault from the server
silo sync login https://silo.example.com -u nikita
silo status                         # same fingerprint on every device

silo sync                           # sync now
silo sync status                    # last sync, changes waiting, errors
silo sync devices                   # this account's devices; --revoke ID locks one out
silo sync logout                    # revoke this device and stop syncing; the vault stays
```

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

### Server deployment

The deployment target is the shared Spectron VPS, with host nginx terminating
TLS for `silo.warpunit.com`. The server runs in Docker Compose and publishes
only `127.0.0.1:8787` on the host. Inside the container it listens on
`0.0.0.0:8787`, so Docker can forward that loopback port to it.

`deployment/compose.yaml` requires `SERVER_IMAGE` (the release image reference).
The non-root process defaults to UID/GID 10001; `SILO_UID` and `SILO_GID` can
match the provisioned host user. Provisioning must create private writable bind
mount directories before starting Compose:

- `/data/silo/db` → `/data/db`: `silo-server.db`, including SQLite WAL files.
- `/data/silo/files` → `/data/files`: reserved for future file storage; the
  current sync server stores encrypted file contents in SQLite too.

`DB_DATA`, `FILES_DATA` and `SERVER_PORT` override those defaults for local
testing. Production logs use Docker's `journald` driver; read them with
`journalctl CONTAINER_NAME=silo-server-1` (the default Compose container name).
Set `LOG_DRIVER=local` on Docker Desktop. The image includes `sqlite3` for online
backups and `curl` for its health check. On the VPS, create invites with
`cd /opt/silo/current && docker compose exec server silo-server invite`.

Build and smoke-test locally without changing the installed Mac CLI:

```sh
docker build -f deployment/Dockerfile -t silo-server:local .
docker run -d --name silo-server-test -p 127.0.0.1:18787:8787 \
  -v silo-server-test-db:/data/db silo-server:local
curl --fail --retry 10 --retry-connrefused --retry-delay 1 http://localhost:18787/health
docker exec silo-server-test silo-server invite
docker restart silo-server-test
curl --fail --retry 10 --retry-connrefused --retry-delay 1 http://localhost:18787/health
docker exec silo-server-test sqlite3 /data/db/silo-server.db 'SELECT count(*) FROM invites;'
docker rm -f silo-server-test
docker volume rm silo-server-test-db
```

Every PR and push to `main` runs formatting, clippy, native build/tests,
container health/persistence, and isolated Debian provisioning/backup checks.
The same reusable checks gate version tag releases before the release image
is built or deployed. The scripts below prepare the host and GitHub production
environment, then deploy over SSH when a version tag is pushed.

### Provisioning the shared VPS

The current host is Debian 13 on amd64, reached as `root@$SSH_HOST` for
provisioning. Docker, Compose and nginx must already be installed and running.
`provision.sh` adds Silo's account, directories, backup units and one nginx
site. Existing project sites, Docker daemon settings, SSH policy and firewall
are retained. The only package installs are missing SQLite, certbot and CA
certificates. nginx is validated before every reload; a failed render or
certificate issuance restores the previous Silo site configuration.

Prepare workstation settings and a dedicated deployment key once:

```sh
cp deployment/.env.example deployment/.env.production
# Fill in SSH_HOST in deployment/.env.production.
chmod 600 deployment/.env.production
ssh-keygen -t ed25519 -N '' -C github-deploy@silo -f deployment/github_deploy_key
deployment/provision.sh --check
```

`.env.production` and both key files are gitignored and excluded from Docker
build contexts. Settings use literal `KEY=value` lines with optional surrounding
quotes, full-line comments and no shell expansion. Exported shell variables
override the file. Connect to the VPS once with SSH and verify its host key
before provisioning; the script requires a known host and key authentication.
The private deployment key stays on the workstation until the GitHub secrets
setup step. Provisioning uploads only its public half.

Once the domain's A record points to the VPS (and any AAAA record also reaches
this host), run:

```sh
deployment/provision.sh
# Repeat the same command to verify a rerun preserves data and authorized keys.
deployment/provision.sh
ssh root@YOUR_VPS_IP 'nginx -t; systemctl list-timers silo-backup.timer; stat -c "%a %U:%G %n" /data/silo /data/silo/db /data/silo/files /data/silo/backups'
curl -I https://silo.warpunit.com/health
```

The script creates `silodev` with UID/GID 10001 (configurable before the first
provision) and adds it to the existing Docker group for deployment. Docker
access grants control of the host; use only the dedicated deployment key for
this account. `/opt/silo` and the three `/data/silo` subdirectories are private
to `silodev` (0700). Reruns append no duplicate key, preserve database/files
contents, and refuse existing data directories owned by another UID/GID.
Docker's restart policy manages the server process; systemd manages the backup
timer. A failed provision retains its remote staging/rollback files for inspection.

The nginx files are `/etc/nginx/sites-available/silo.warpunit.com.conf` and its
matching symlink in `sites-enabled`. TLS uses certbot's webroot mode at
`/var/www/silo-acme`, with the host's renewal timer and a Silo reload hook. HTTPS
returns **502 until the first application deployment**; this is expected at
the provisioning stage. The browser or curl should still validate the TLS
certificate. `--skip-certs` prepares the host before DNS is ready, serving 503
on HTTP when no certificate exists. `--nginx-only` updates the proxy using an
existing certificate; `--backups-only` updates the backup script and timer.

### SQLite backups

`silo-backup.timer` runs an online `sqlite3 .backup` at 03:30 UTC plus a random
delay of up to 15 minutes, keeping 14 days of snapshots by default
(`BACKUP_KEEP_DAYS`). The oneshot service runs as `silodev`; snapshots are mode
0600 in `/data/silo/backups`. Each snapshot is checked with
`PRAGMA integrity_check` and renamed into place only after success. A missing
database is skipped without creating an empty database. Committed WAL contents
are included without stopping the server.

After the first deployment, test it manually:

```sh
ssh root@YOUR_VPS_IP 'systemctl start silo-backup.service; journalctl -u silo-backup.service -n 20 --no-pager; ls -l /data/silo/backups'
```

Snapshots cover the entire current sync store, including encrypted file
contents; `/data/silo/files` is reserved and currently unused. These snapshots
stay on the same VPS; copy them off the host for disaster recovery. To restore,
stop Silo, retain the old database and its WAL/SHM sidecars together in a
separate directory, and install the checked snapshot as
`/data/silo/db/silo-server.db` owned by `silodev`, mode 0600, before restarting.

Run the provisioning tests without contacting the VPS:

```sh
python3 deployment/tests/config.py
docker build -f deployment/tests/Dockerfile -t silo-provision:check .
docker run --rm silo-provision:check
```

The disposable Debian test uses real accounts, nginx validation, private data
directories, SQLite backups and release symlinks. Docker/systemd, SSH and HTTPS
boundaries are stubbed. It checks provisioning reruns, nginx rollback without
changing another site, WAL snapshots, failed image pulls and backups, recovery
after container/HTTPS health failures, and temporary registry credential cleanup.

### GitHub deployment settings

After provisioning, validate access and then upload production settings:

```sh
gh auth login --hostname github.com  # skip if already authenticated
deployment/github-env.sh --check
deployment/github-env.sh
```

The helper reads the same ignored `.env.production`, defaulting to repository
`niklucky/silo` (`GITHUB_REPO` overrides it). It checks that the unencrypted
deployment private key works as `silodev` and that this user can access Docker
and Compose before changing GitHub. `--check` performs read-only checks.
It works from any directory; paths in the env file are relative to the repo
root, or absolute.

The `production` environment receives secrets `SSH_HOST`, `SSH_PRIVATE_KEY`
and `SSH_KNOWN_HOSTS`, plus variables `SSH_USER`, `SSH_PORT`, `DOMAIN`,
`SERVER_PORT`, `SILO_UID` and `SILO_GID`. The key is read directly from
`SSH_PRIVATE_KEY_PATH` on stdin; secret values are not printed or put in
command arguments. Host keys are taken from the already trusted entry for the
configured host and port in `~/.ssh/known_hosts` (or `SSH_KNOWN_HOSTS_PATH`).
Hashed entries and non-default SSH ports are supported. A missing, changed or
revoked host key fails the check; verify a changed key before updating your
trust store and rerunning the helper.

Reruns overwrite only the listed secrets and variables. Existing environment
protection rules and unrelated settings are retained. Review the result at
<https://github.com/niklucky/silo/settings/environments>, or list names without
reading secret values:

```sh
gh secret list --repo niklucky/silo --env production
gh variable list --repo niklucky/silo --env production
```

Uploading settings does not start a deployment.

### Version releases and updates

After the deployment changes are committed, merged and checked on `main`,
push a version tag to release and deploy:

```sh
git switch main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
gh run list --repo niklucky/silo --workflow release.yml --limit 5
```

Use a new `vX.Y.Z` tag for each update; do not move published tags. Other tag
names beginning with `v` fail validation before building or deploying.
`.github/workflows/release.yml` runs the existing checks, publishes an
`linux/amd64` image at `ghcr.io/niklucky/silo/server` tagged with both the
version and commit SHA, and health-checks the published image on the runner.
The deploy job runs in the `production` GitHub environment and passes the
image's immutable `@sha256:…` digest to the VPS. The workflow's scoped
`GITHUB_TOKEN` supplies registry access; no registry password or PAT is needed.

Each SSH deployment creates a private
`/opt/silo/releases/<version>-<commit>.<unique-suffix>` directory containing
`compose.yaml`, `.env`, and the deploy scripts. SSH requires the pinned
`SSH_KNOWN_HOSTS`; there is no keyscan fallback. The registry login uses a
temporary `.registry` directory inside this release, deleted on success and
failure. A lost SSH connection can prevent cleanup; the workflow reports the
exact path to inspect and delete. Runner SSH key files are temporary too.

The remote script takes a host lock, validates the Compose configuration and
data directory owners, pulls the new image, then runs `silo-backup` with the
configured retention before changing the container. A pull or backup failure
leaves the existing process running. Compose waits up to 120 seconds for
container health; the script also checks `https://silo.warpunit.com/health`
through nginx. Success atomically updates `/opt/silo/current`, retaining
`/opt/silo/previous`. A GitHub Release containing the commit and image digest
is published only after deployment succeeds. The workflow queues release runs
instead of canceling a deployment in progress, using GitHub's
[`queue: max` concurrency setting](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency).

If container or HTTPS health fails, the script prints recent logs and attempts
to restart the previous release using its cached image. An unsuccessful first
deployment stops the failed container. The current symlink stays at the last
successful release. Recovery keeps the live database: it never automatically
restores a snapshot, which could discard writes received after the backup.
If a future release migrates the SQLite schema, the older server may refuse
the newer schema; inspect the logs and follow the explicit restore procedure
above if a database restore is necessary.

For a failed workflow, rerun the failed jobs from the Actions run. A new remote
release directory is created each time. A full rerun rebuilds the image from
the same source commit and may pick up newer base image packages; it can have
a different digest, recorded in that release's notes. Successful releases and
cached images are retained on the host; the deploy script does not prune
shared-host images or delete database files.

Inspect the running release, logs and backups after the first deployment:

```sh
curl --fail https://silo.warpunit.com/health
ssh -i deployment/github_deploy_key -o IdentitiesOnly=yes silodev@YOUR_VPS_IP \
  'cd /opt/silo/current && cat .env && docker compose ps && docker compose exec -T server silo-server invite'
ssh root@YOUR_VPS_IP \
  'journalctl CONTAINER_NAME=silo-server-1 -n 30 --no-pager; systemctl start silo-backup.service; ls -l /data/silo/backups'
```

The `.env` inside a remote release contains only image/deployment metadata,
never the SSH private key or registry token. The invite is a one-time account
code, valid for seven days.

Local checks before committing the release setup:

```sh
shellcheck -x deployment/*.sh deployment/tests/*.sh
python3 deployment/tests/config.py
python3 deployment/tests/github_env.py
docker build -f deployment/tests/Dockerfile -t silo-provision:check .
docker run --rm silo-provision:check
# actionlint 1.7.12 does not yet recognize GitHub's queue property:
actionlint -ignore 'unexpected key "queue" for "concurrency" section'
```

### First production sync test

On the Mac with your existing unlocked vault, register using the invite above:

```sh
silo sync register https://silo.warpunit.com -u YOUR_USERNAME --invite YOUR_INVITE
silo sync
silo status
```

In a second terminal, use an empty, separate data directory and socket. Log in
with the same username and vault password; do not run `silo init` first:

```sh
export SILO_HOME="$(mktemp -d /tmp/silo-second.XXXXXXXX)"
export SILO_AGENT_SOCKET="$SILO_HOME/agent.sock"
silo sync login https://silo.warpunit.com -u YOUR_USERNAME
silo status
```

The fingerprints must match. Keep that terminal's variables set while testing.
On the first terminal, create a harmless test note and sync it:

```sh
silo add note deployment/test --text 'from first vault'
silo sync
```

In the second terminal, run `silo sync`, then
`silo get deployment/test`; expect the first text. Edit it using
`silo edit deployment/test --text 'from second vault'`, then `silo sync`.
Sync and read it in the first terminal; expect the new text. Reverse the edit
once more to verify both directions. Delete the note in the second terminal
with `silo rm deployment/test --yes`, sync both terminals and verify it is
absent on the first. Create a second note at `deployment/test-delete`, sync
both, delete it on the first, then sync both and verify it is absent on the
second. `silo status` should still show matching fingerprints.

When done, in the second terminal run `silo sync logout` and
`silo agent stop`. Its temporary directory remains for inspection. These
steps do not replace the installed Mac CLI or restart the primary agent.

## Browser extension: HTTP Basic Auth

The extension answers `401` challenges with a saved login so the browser never
shows its password dialog. It holds no keys: it asks the agent, through a
native-messaging bridge, for the best login for the URL being loaded.

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
  `match` (optionally with same-site logins). `update` re-seals under a fresh
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

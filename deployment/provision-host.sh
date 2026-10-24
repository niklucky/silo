#!/usr/bin/env bash
# Internal remote half; use provision.sh from the workstation.
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die 'Root privileges required'
STAGE=${1:?Staging directory required}
# Generated with printf %q from validated settings, never from an env file.
# shellcheck source=/dev/null
. "$STAGE/settings.sh"
# shellcheck source=/dev/null
. /etc/os-release
if [ "$ID" != debian ] || [ "$VERSION_ID" != 13 ]; then die 'Expected Debian 13'; fi
exec 9>/run/lock/silo-provision.lock
flock -n 9 || die 'Another Silo provision is active'

# This is an existing shared Docker/nginx host. Do not replace, restart or
# reconfigure its Docker daemon, SSH policy, firewall, or other nginx sites.
for command in docker nginx ss flock; do
  command -v "$command" >/dev/null || die "Missing $command on the existing host"
done
docker info >/dev/null
docker compose version >/dev/null
nginx -t
if [ "$MODE" = full ]; then
  if id silodev >/dev/null 2>&1; then
    if [ "$(id -u silodev)" != "$SILO_UID" ] || [ "$(id -g silodev)" != "$SILO_GID" ]; then
      die 'silodev UID/GID does not match configuration'
    fi
  else
    ! getent passwd "$SILO_UID" >/dev/null || die "UID $SILO_UID is already allocated"
    ! getent group silodev >/dev/null || die 'Group silodev already exists without the user'
    ! getent group "$SILO_GID" >/dev/null || die "GID $SILO_GID is already allocated"
  fi
  if [ ! -L /opt/silo/current ] && [ -n "$(ss -ltnH "sport = :$SERVER_PORT")" ]; then
    die "Port $SERVER_PORT is already in use; choose a free SERVER_PORT"
  fi
  for path in /data/silo /data/silo/db /data/silo/files /data/silo/backups /opt/silo /opt/silo/releases; do
    [ ! -L "$path" ] || die "Refusing symlink: $path"
  done

  missing=()
  for package in sqlite3 certbot ca-certificates; do
    if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]; then
      missing+=("$package")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    apt-get update
    apt-get install -y --no-install-recommends "${missing[@]}"
  fi
  if ! id silodev >/dev/null 2>&1; then
    groupadd --gid "$SILO_GID" silodev
    useradd --uid "$SILO_UID" --gid silodev --create-home --shell /bin/bash silodev
  fi
  usermod -aG docker silodev
  home=$(getent passwd silodev | cut -d: -f6)
  if [ ! -d "$home" ] || [ -L "$home/.ssh" ]; then die 'Invalid silodev home/.ssh'; fi
  install -d -o silodev -g silodev -m 0700 "$home/.ssh"
  [ ! -L "$home/.ssh/authorized_keys" ] || die 'authorized_keys must not be a symlink'
  touch "$home/.ssh/authorized_keys"
  key=$(cat "$STAGE/deploy.pub")
  if ! grep -qxF -- "$key" "$home/.ssh/authorized_keys"; then
    printf '\n%s\n' "$key" >> "$home/.ssh/authorized_keys"
  fi
  chown silodev:silodev "$home/.ssh/authorized_keys"
  chmod 0600 "$home/.ssh/authorized_keys"
  install -d -o silodev -g silodev -m 0700 /opt/silo /opt/silo/releases /data/silo
  for path in /data/silo/db /data/silo/files /data/silo/backups; do
    if [ -d "$path" ]; then
      [ "$(stat -c %u:%g "$path")" = "$SILO_UID:$SILO_GID" ] || die "Unexpected owner on $path; inspect existing data before changing ownership"
      chmod 0700 "$path"
    else
      install -d -o silodev -g silodev -m 0700 "$path"
    fi
  done
fi

if [ "$MODE" = full ] || [ "$MODE" = backups ]; then
  id silodev >/dev/null || die 'Run a full provision first'
  command -v sqlite3 >/dev/null || die 'Run a full provision to install sqlite3'
  install -m 0755 "$STAGE/backup.sh" /usr/local/bin/silo-backup
  install -d -m 0755 /etc/silo
  printf 'KEEP_DAYS=%s\n' "$BACKUP_KEEP_DAYS" > /etc/silo/backup.env
  chmod 0644 /etc/silo/backup.env
  cat > /etc/systemd/system/silo-backup.service <<'UNIT'
[Unit]
Description=Online SQLite backup for Silo

[Service]
Type=oneshot
User=silodev
Group=silodev
UMask=0077
EnvironmentFile=/etc/silo/backup.env
ExecStart=/usr/local/bin/silo-backup
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/data/silo/db /data/silo/backups
UNIT
  cat > /etc/systemd/system/silo-backup.timer <<'UNIT'
[Unit]
Description=Nightly Silo SQLite backup

[Timer]
OnCalendar=*-*-* 03:30:00 UTC
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  chmod 0644 /etc/systemd/system/silo-backup.{service,timer}
  systemctl daemon-reload
  systemctl enable --now silo-backup.timer
fi
[ "$MODE" != backups ] || exit 0

available="/etc/nginx/sites-available/$DOMAIN.conf"
enabled="/etc/nginx/sites-enabled/$DOMAIN.conf"
for site in /etc/nginx/sites-enabled/*; do
  [ -f "$site" ] || continue
  if [ "$site" != "$enabled" ] && grep -Fq -- "$DOMAIN" "$site"; then
    die "Domain already mentioned in $site; inspect it before provisioning"
  fi
done
[ ! -L "$available" ] || die "Refusing symlink: $available"
if [ -e "$enabled" ] || [ -L "$enabled" ]; then
  if [ ! -L "$enabled" ] || [ "$(readlink "$enabled")" != "$available" ]; then die "Refusing to replace $enabled"; fi
fi
has_cert() {
  [ -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] && [ -s "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]
}
[ "$MODE" != nginx ] || has_cert || die 'Missing certificate; run a full provision after DNS is ready'

had_file=0
had_link=0
[ ! -f "$available" ] || { cp -p "$available" "$STAGE/nginx.previous"; had_file=1; }
[ ! -L "$enabled" ] || had_link=1
pending=1
rollback() {
  local rc=$?
  trap - EXIT
  if [ "$pending" = 1 ]; then
    if [ "$had_file" = 1 ]; then cp -p "$STAGE/nginx.previous" "$available"; else rm -f -- "$available"; fi
    [ "$had_link" = 1 ] || rm -f -- "$enabled"
    nginx -t && systemctl reload nginx || echo 'Silo nginx rollback needs attention' >&2
  fi
  exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
render() {
  local response='return 503;'
  # These are nginx variables, not shell substitutions.
  # shellcheck disable=SC2016
  has_cert && response='return 301 https://$host$request_uri;'
  sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s|__HTTP_RESPONSE__|$response|g" "$STAGE/nginx/http.conf" > "$available"
  if has_cert; then
    sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__SERVER_PORT__/$SERVER_PORT/g" "$STAGE/nginx/https.conf" >> "$available"
  fi
  chmod 0644 "$available"
  ln -sfn "$available" "$enabled"
  nginx -t
  systemctl reload nginx
}
install -d -m 0755 /var/www/silo-acme
render
if [ "$MODE" = full ] && [ "$SKIP_CERTS" = 0 ]; then
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/silo-nginx <<'HOOK'
#!/bin/sh
set -eu
nginx -t
systemctl reload nginx
HOOK
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/silo-nginx
  args=(--cert-name "$DOMAIN" -d "$DOMAIN")
  if [ -n "$CERT_EMAIL" ]; then args+=(--email "$CERT_EMAIL"); else args+=(--register-unsafely-without-email); fi
  certbot certonly --webroot -w /var/www/silo-acme "${args[@]}" \
    --agree-tos --non-interactive --keep-until-expiring
  render
  systemctl enable --now certbot.timer
fi
pending=0
printf 'Silo host ready: silodev UID/GID %s:%s, localhost:%s, domain %s\n' "$SILO_UID" "$SILO_GID" "$SERVER_PORT" "$DOMAIN"
printf 'Provisioning does not deploy/restart Silo. Without a certificate HTTP returns 503; HTTPS returns 502 until a server is deployed.\n'

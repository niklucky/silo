#!/usr/bin/env bash
# Remote entry point, shipped to a new /opt/silo/releases directory each run.
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
case "$HERE" in /opt/silo/releases/*) ;; *) echo 'Run from /opt/silo/releases/<release>/deploy.sh' >&2; exit 1 ;; esac
# shellcheck source=deployment/config.sh
. "$HERE/config.sh"
load_config "$HERE/.env"
setting SERVER_IMAGE
setting RELEASE_VERSION
setting RELEASE_SHA
validate_release
[ "$(id -un)" = silodev ] || die 'Deploy as silodev'

exec 9>/opt/silo/.deploy.lock
flock -w 120 9 || die 'Another Silo deployment is active'
for path in /data/silo/db /data/silo/files /data/silo/backups; do
  [ -d "$path" ] && [ ! -L "$path" ] || die "Missing provisioned directory: $path"
  [ "$(stat -c %u:%g "$path")" = "$SILO_UID:$SILO_GID" ] || die "Unexpected owner on $path"
done
previous=''
if [ -L /opt/silo/current ]; then
  previous=$(readlink -f /opt/silo/current)
  case "$previous" in /opt/silo/releases/*) ;; *) die 'Invalid current release link' ;; esac
  [ -f "$previous/.env" ] && [ -f "$previous/compose.yaml" ] || die 'Current release is incomplete'
elif [ -e /opt/silo/current ]; then
  die '/opt/silo/current must be a release symlink'
fi

compose() {
  local directory="$1"
  shift
  docker compose --project-name silo --project-directory "$directory" \
    --env-file "$directory/.env" -f "$directory/compose.yaml" "$@"
}

# Pull failures and failed backups leave the current server untouched.
compose "$HERE" config --quiet
compose "$HERE" pull --quiet
backup_keep=$(env_value /etc/silo/backup.env KEEP_DAYS)
KEEP_DAYS="$backup_keep" /usr/local/bin/silo-backup

changed=0
finish() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && [ "$changed" = 1 ]; then
    compose "$HERE" logs --tail 100 server >&2 || true
    if [ -n "$previous" ]; then
      printf 'Deployment failed; restarting previous release %s\n' "$previous" >&2
      compose "$previous" up --detach --wait --wait-timeout 120 --pull never >&2 \
        || echo 'Previous server could not restart; inspect logs and the pre-deploy backup' >&2
    else
      compose "$HERE" stop server >&2 || true
    fi
  fi
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
changed=1
compose "$HERE" up --detach --wait --wait-timeout 120 --pull never
# Check TLS/nginx as well as the container's internal health endpoint.
healthy=0
for attempt in $(seq 1 10); do
  printf 'HTTPS health check %s/10\n' "$attempt"
  if curl --fail --silent --show-error --max-time 5 "https://$DOMAIN/health" | grep -q '"status":"ok"'; then
    healthy=1
    break
  fi
  sleep 2
done
[ "$healthy" = 1 ] || die 'Public HTTPS health check failed'
compose "$HERE" ps
if [ -n "$previous" ] && [ "$previous" != "$HERE" ]; then
  ln -s "$previous" "$HERE/previous-link"
  mv -Tf "$HERE/previous-link" /opt/silo/previous
fi
ln -s "$HERE" "$HERE/current-link"
mv -Tf "$HERE/current-link" /opt/silo/current
changed=0
printf 'Deployed %s (%s): %s\n' "$RELEASE_VERSION" "$RELEASE_SHA" "$SERVER_IMAGE"

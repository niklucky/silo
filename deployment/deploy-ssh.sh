#!/usr/bin/env bash
# GitHub runner entry point. All secrets are supplied as environment variables.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deployment/config.sh
. "$HERE/config.sh"
load_config "$HERE/.env.example"
: "${SSH_PRIVATE_KEY:?Set SSH_PRIVATE_KEY}"
: "${SSH_KNOWN_HOSTS:?Set SSH_KNOWN_HOSTS}"
: "${GHCR_TOKEN:?Set GHCR_TOKEN}"
: "${GHCR_USER:?Set GHCR_USER}"
: "${SERVER_IMAGE:?Set SERVER_IMAGE}"
: "${RELEASE_VERSION:?Set RELEASE_VERSION}"
: "${RELEASE_SHA:?Set RELEASE_SHA}"
validate_release
[[ "$GHCR_USER" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\[bot\])?$ ]] || die 'Invalid registry username'
umask 077
work=$(mktemp -d)
stage=''
ssh_opts=(-T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=15 -o "UserKnownHostsFile=$work/known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -i "$work/key" -p "$SSH_PORT")
target="$SSH_USER@$SSH_HOST"
# Remote paths and arguments interpolated below are validated or mktemp output.
# shellcheck disable=SC2029
remote() { ssh "${ssh_opts[@]}" "$target" "$@"; }
cleanup() {
  local rc=$?
  trap - EXIT
  if [ -n "$stage" ]; then
    if ! remote "find '$stage/.registry' -depth -delete" >/dev/null 2>&1; then
      printf 'Could not remove temporary registry credentials at %s/.registry\n' "$stage" >&2
      rc=1
    fi
  fi
  find "$work" -depth -delete
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' "$SSH_PRIVATE_KEY" > "$work/key"
printf '%s\n' "$SSH_KNOWN_HOSTS" > "$work/known_hosts"
ssh-keygen -y -P '' -f "$work/key" >/dev/null 2>&1 || die 'Invalid deployment private key'

mkdir "$work/bundle"
cp "$HERE/deploy.sh" "$HERE/config.sh" "$HERE/compose.yaml" "$work/bundle/"
{
  # Remote config validation needs a hostname; this value is not used to connect.
  printf 'SSH_HOST=localhost\n'
  for name in SERVER_IMAGE RELEASE_VERSION RELEASE_SHA DOMAIN SILO_UID SILO_GID SERVER_PORT; do
    printf '%s=%s\n' "$name" "${!name}"
  done
} > "$work/bundle/.env"
stage=$(remote "umask 077; mktemp -d /opt/silo/releases/$RELEASE_VERSION-$RELEASE_SHA.XXXXXXXX")
case "$stage" in
  /opt/silo/releases/"$RELEASE_VERSION-$RELEASE_SHA".????????) ;;
  *) stage=''; die 'Unexpected remote release directory' ;;
esac
case "$stage" in *[!a-zA-Z0-9/._-]*) stage=''; die 'Unsafe remote release directory' ;; esac
COPYFILE_DISABLE=1 tar -C "$work/bundle" -cf - . | remote "tar -C '$stage' -xf -"
remote "install -m 700 -d '$stage/.registry'"
printf '%s' "$GHCR_TOKEN" | remote \
  "DOCKER_CONFIG='$stage/.registry' docker login ghcr.io --username '$GHCR_USER' --password-stdin"
# Run a file: Compose must never consume the rest of a script arriving on stdin.
remote "DOCKER_CONFIG='$stage/.registry' bash '$stage/deploy.sh'" </dev/null

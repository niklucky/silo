#!/usr/bin/env bash
# Populate only Silo's production environment. Secret values travel on stdin.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
# shellcheck source=deployment/config.sh
. "$HERE/config.sh"

ENV_FILE="$HERE/.env.production"
CHECK=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    --env-file=*) ENV_FILE=${arg#*=} ;;
    -h|--help)
      printf '%s\n' 'Usage: deployment/github-env.sh [--check] [--env-file=PATH]' \
        '  --check: validate settings, GitHub access and deployment SSH without writing anything'
      exit 0 ;;
    *) die "Unknown option: $arg" ;;
  esac
done
load_config "$ENV_FILE"
setting GITHUB_REPO niklucky/silo
setting SSH_KNOWN_HOSTS_PATH "$HOME/.ssh/known_hosts"
[[ "$GITHUB_REPO" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*/[a-zA-Z0-9_][a-zA-Z0-9._-]*$ ]] || die 'GITHUB_REPO must be OWNER/REPO on github.com'

resolve_path() {
  case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$ROOT" "$1" ;; esac
}
key=$(resolve_path "$SSH_PRIVATE_KEY_PATH")
known=$(resolve_path "$SSH_KNOWN_HOSTS_PATH")
[ -s "$key" ] || die "Missing deployment private key: $key"
[ -s "$known" ] || die "Missing SSH trust store: $known; connect to the VPS and verify its host key first"
# Fail before changing GitHub if the file is not an unencrypted private key.
ssh-keygen -y -P '' -f "$key" >/dev/null 2>&1 || die 'Deployment key must be a readable, unencrypted private key with private permissions'
lookup="$SSH_HOST"
[ "$SSH_PORT" = 22 ] || lookup="[$SSH_HOST]:$SSH_PORT"

umask 077
pin=$(mktemp)
trap 'rm -f -- "$pin"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ssh-keygen -F "$lookup" -f "$known" | sed '/^#/d' > "$pin" || die 'No trusted key for this SSH_HOST/SSH_PORT; connect with SSH and verify the host key first'
[ -s "$pin" ] || die 'No trusted VPS host key found'
! grep -q '^@revoked ' "$pin" || die 'The VPS host key is marked revoked'
command -v gh >/dev/null || die 'Install the GitHub CLI first'
export GH_HOST=github.com
gh auth status --hostname github.com >/dev/null 2>&1 || die 'Run gh auth login --hostname github.com first'
# An explicit repository keeps this independent of the caller working directory.
environments=$(gh api "repos/$GITHUB_REPO/environments" --paginate --jq '.environments[].name')

printf 'Checking dedicated deployment SSH access to %s@%s:%s\n' "$SSH_USER" "$SSH_HOST" "$SSH_PORT"
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=15 -o "UserKnownHostsFile=$pin" -o GlobalKnownHostsFile=/dev/null \
  -i "$key" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
  'test "$(id -un)" = silodev && docker info >/dev/null && docker compose version'
printf 'Target: https://github.com/%s/settings/environments (production)\n' "$GITHUB_REPO"
printf '%s\n' 'Secrets: SSH_HOST, SSH_PRIVATE_KEY, SSH_KNOWN_HOSTS' \
  'Variables: SSH_USER, SSH_PORT, DOMAIN, SERVER_PORT, SILO_UID, SILO_GID'
if [ "$CHECK" = 1 ]; then
  printf 'Preflight passed; no GitHub settings changed.\n'
  exit 0
fi

if ! printf '%s\n' "$environments" | grep -qx production; then
  gh api --method PUT "repos/$GITHUB_REPO/environments/production" --silent
fi
# Do not PUT an existing environment: preserve its protection rules.
printf '%s' "$SSH_HOST" | gh secret set SSH_HOST --repo "$GITHUB_REPO" --env production
gh secret set SSH_PRIVATE_KEY --repo "$GITHUB_REPO" --env production < "$key"
gh secret set SSH_KNOWN_HOSTS --repo "$GITHUB_REPO" --env production < "$pin"
for name in SSH_USER SSH_PORT DOMAIN SERVER_PORT SILO_UID SILO_GID; do
  gh variable set "$name" --repo "$GITHUB_REPO" --env production --body "${!name}"
done
printf 'Production environment configured. Rerun this command to update settings or rotate the key.\n'

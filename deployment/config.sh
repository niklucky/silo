# shellcheck shell=bash
# Shared by workstation deployment tools. Compatible with macOS bash 3.2.
# Never source an env file: pasted values must not execute shell expressions.
env_value() {
  awk -v key="$2" '
    { sub(/\r$/, "") }
    $0 ~ "^[[:space:]]*" key "=" {
      value = substr($0, index($0, "=") + 1)
      if ((substr(value, 1, 1) == "\"" && substr(value, length(value), 1) == "\"") ||
          (substr(value, 1, 1) == "\047" && substr(value, length(value), 1) == "\047"))
        value = substr(value, 2, length(value) - 2)
      found = value
    }
    END { printf "%s", found }
  ' "$1"
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

setting() {
  local name="$1" fallback="${2-}" value
  [ -z "${!name+set}" ] || return 0
  value=$(env_value "$ENV_FILE" "$name")
  [ -n "$value" ] || value="$fallback"
  printf -v "$name" '%s' "$value"
}

load_config() {
  ENV_FILE="$1"
  [ -f "$ENV_FILE" ] || die "Missing $ENV_FILE; copy deployment/.env.example first"
  setting SSH_HOST
  setting SSH_PORT 22
  setting PROVISION_USER root
  setting SSH_USER silodev
  setting DEPLOY_PUBLIC_KEY_PATH deployment/github_deploy_key.pub
  setting SSH_PRIVATE_KEY_PATH deployment/github_deploy_key
  setting DOMAIN silo.warpunit.com
  setting CERT_EMAIL
  setting SILO_UID 10001
  setting SILO_GID 10001
  setting SERVER_PORT 8787
  setting BACKUP_KEEP_DAYS 14

  case "$SSH_HOST" in ''|*[!a-zA-Z0-9.-]*|-*) die 'SSH_HOST must be an IPv4 address or hostname' ;; esac
  case "$PROVISION_USER" in ''|*[!a-z0-9_-]*|-*) die 'Invalid PROVISION_USER' ;; esac
  [ "$SSH_USER" = silodev ] || die 'This deployment uses the dedicated silodev account'
  case "$DOMAIN" in ''|*[!a-z0-9.-]*|.*|-*|*..*|*.) die 'Invalid DOMAIN' ;; esac
  case "$DOMAIN" in *.*) ;; *) die 'DOMAIN must be a fully qualified hostname' ;; esac
  for name in SSH_PORT SERVER_PORT SILO_UID SILO_GID BACKUP_KEEP_DAYS; do
    value=${!name}
    case "$value" in ''|*[!0-9]*|0*) die "$name must be a positive decimal integer" ;; esac
    [ "${#value}" -le 5 ] && [ "$value" -le 65535 ] || die "$name is out of range"
  done
  [ "$SILO_UID" -ge 1000 ] && [ "$SILO_GID" -ge 1000 ] || die 'Use a non-system UID/GID (at least 1000)'
  if [ -n "$CERT_EMAIL" ]; then
    case "$CERT_EMAIL" in *[!a-zA-Z0-9._%+@-]*) die 'Invalid CERT_EMAIL' ;; esac
    case "$CERT_EMAIL" in ?*@?*.?*) ;; *) die 'Invalid CERT_EMAIL' ;; esac
  fi
}

#!/usr/bin/env bash
# The release job fills in the version, repository and SHA-256 digests.
# Invoke only after the shell has received the complete function definition.
install_silo() (
  set -eu
  version='@VERSION@'
  repository='@REPOSITORY@'
  platform=$(uname -s)
  arch=$(uname -m)
  case "$platform/$arch" in
    Linux/x86_64) asset=silo-linux-x64; expected='@LINUX_X64@' ;;
    Darwin/arm64) asset=silo-macos-arm64; expected='@MACOS_ARM64@' ;;
    Darwin/x86_64) asset=silo-macos-x64; expected='@MACOS_X64@' ;;
    *) printf 'No Silo CLI binary for %s/%s\n' "$platform" "$arch" >&2; exit 1 ;;
  esac

  dest=${SILO_INSTALL_DIR:-"$HOME/.local/bin"}
  mkdir -p -- "$dest"
  if [[ -d "$dest/silo" ]]; then
    printf 'Installation path is a directory: %s/silo\n' "$dest" >&2
    exit 1
  fi
  tmp=$(mktemp "$dest/.silo.XXXXXXXX")
  trap 'rm -f -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM

  url="https://github.com/$repository/releases/download/$version/$asset"
  if command -v curl >/dev/null 2>&1; then
    curl -qfsSL --proto '=https' --proto-redir '=https' --output "$tmp" "$url"
  else
    wget -qO "$tmp" "$url"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum < "$tmp")
  else
    actual=$(shasum -a 256 < "$tmp")
  fi
  if [[ ${actual%% *} != "$expected" ]]; then
    printf 'SHA-256 verification failed for %s\n' "$asset" >&2
    exit 1
  fi
  chmod 755 "$tmp"
  mv -f -- "$tmp" "$dest/silo"
  printf 'Installed Silo CLI %s at %s/silo\n' "$version" "$dest"
)

install_silo

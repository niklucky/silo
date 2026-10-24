#!/usr/bin/env bash
# Installed at /usr/local/bin/silo-backup; also run before a deployment.
set -euo pipefail
umask 077
DB=${DB:-/data/silo/db/silo-server.db}
BACKUP_DIR=${BACKUP_DIR:-/data/silo/backups}
KEEP_DAYS=${KEEP_DAYS:-14}
case "$BACKUP_DIR" in /*) ;; *) echo 'BACKUP_DIR must be absolute' >&2; exit 1 ;; esac
case "$BACKUP_DIR" in *[!a-zA-Z0-9/._-]*) echo 'Invalid BACKUP_DIR' >&2; exit 1 ;; esac
case "$KEEP_DAYS" in ''|*[!0-9]*|0*) echo 'Invalid KEEP_DAYS' >&2; exit 1 ;; esac
# Opening a missing SQLite path would create a new empty database.
[ -s "$DB" ] || { echo "No database at $DB; nothing to back up"; exit 0; }
mkdir -p "$BACKUP_DIR"
exec 9>"$BACKUP_DIR/.backup.lock"
flock -w 30 9
partial=$(mktemp "$BACKUP_DIR/.silo-backup.XXXXXXXX")
trap 'rm -f -- "$partial"' EXIT
sqlite3 -cmd '.timeout 10000' "$DB" ".backup '$partial'"
[ "$(sqlite3 "$partial" 'PRAGMA integrity_check;')" = ok ] || { echo 'Backup integrity check failed' >&2; exit 1; }
target="$BACKUP_DIR/silo-$(date -u +%Y%m%dT%H%M%S)-${partial##*.}.db"
mv "$partial" "$target"
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'silo-*.db' -mtime +"$KEEP_DAYS" -delete
printf 'SQLite backup: %s\n' "$target"

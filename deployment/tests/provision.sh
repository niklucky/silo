#!/usr/bin/env bash
# Run only in the disposable test image; paths below intentionally mirror Debian.
set -euo pipefail
cd /test
mkdir -p /run/lock /run/nginx /stage
cp deployment/provision-host.sh deployment/backup.sh /stage/
cp -R deployment/nginx /stage/
ssh-keygen -q -t ed25519 -N '' -f /tmp/test-deploy-key
cp /tmp/test-deploy-key.pub /stage/deploy.pub
cat > /stage/settings.sh <<'SETTINGS'
MODE=full
SKIP_CERTS=1
DOMAIN=silo.warpunit.com
CERT_EMAIL=
SILO_UID=10001
SILO_GID=10001
SERVER_PORT=8787
BACKUP_KEEP_DAYS=14
SETTINGS
# Service management and Docker are external boundaries. nginx -t, account
# creation, file permissions, SQLite and all provision logic run for real.
cat > /usr/local/bin/docker <<'DOCKER'
#!/bin/sh
case "$1" in info|compose) exit 0 ;; *) exit 1 ;; esac
DOCKER
cat > /usr/local/bin/systemctl <<'SYSTEMCTL'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/systemctl-calls
SYSTEMCTL
chmod +x /usr/local/bin/docker /usr/local/bin/systemctl
groupadd docker
printf 'server { listen 8090; server_name other.example.com; return 204; }\n' > /etc/nginx/sites-available/other.conf
ln -s /etc/nginx/sites-available/other.conf /etc/nginx/sites-enabled/other.conf
other=$(sha256sum /etc/nginx/sites-available/other.conf)

bash /stage/provision-host.sh /stage
[ "$(stat -c %a:%u:%g /data/silo/db)" = 700:10001:10001 ]
[ "$(stat -c %a:%u:%g /data/silo/files)" = 700:10001:10001 ]
grep -q 'return 503;' /etc/nginx/sites-available/silo.warpunit.com.conf
runuser -u silodev -- sqlite3 /data/silo/db/silo-server.db \
  'PRAGMA journal_mode=WAL; CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ("preserved");'
runuser -u silodev -- touch /data/silo/files/preserved
bash /stage/provision-host.sh /stage
[ "$(grep -cF -- "$(cat /stage/deploy.pub)" /home/silodev/.ssh/authorized_keys)" = 1 ]
[ "$(sqlite3 /data/silo/db/silo-server.db 'SELECT value FROM sample;')" = preserved ]
[ -f /data/silo/files/preserved ]

# A TLS render must parse and retain the unrelated site.
mkdir -p /etc/letsencrypt/live/silo.warpunit.com
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=silo.warpunit.com \
  -keyout /etc/letsencrypt/live/silo.warpunit.com/privkey.pem \
  -out /etc/letsencrypt/live/silo.warpunit.com/fullchain.pem 2>/dev/null
printf '\nMODE=nginx\n' >> /stage/settings.sh
bash /stage/provision-host.sh /stage
nginx -t
site=/etc/nginx/sites-available/silo.warpunit.com.conf
grep -q 'proxy_pass http://127.0.0.1:8787;' "$site"
before=$(sha256sum "$site")
cp /stage/nginx/https.conf /tmp/https.good
printf '\ninvalid_test_directive;\n' >> /stage/nginx/https.conf
if bash /stage/provision-host.sh /stage; then echo 'Broken nginx template unexpectedly passed' >&2; exit 1; fi
[ "$(sha256sum "$site")" = "$before" ]
[ "$(sha256sum /etc/nginx/sites-available/other.conf)" = "$other" ]
[ "$(readlink /etc/nginx/sites-enabled/other.conf)" = /etc/nginx/sites-available/other.conf ]
nginx -t

# Certificate issuance errors also roll back just the Silo site.
cp /tmp/https.good /stage/nginx/https.conf
cat > /usr/local/bin/certbot <<'CERTBOT'
#!/bin/sh
echo 'Simulated ACME failure' >&2
exit 1
CERTBOT
chmod +x /usr/local/bin/certbot
printf '\nMODE=full\nSKIP_CERTS=0\n' >> /stage/settings.sh
if bash /stage/provision-host.sh /stage; then echo 'Failed issuance unexpectedly passed' >&2; exit 1; fi
[ "$(sha256sum "$site")" = "$before" ]
[ "$(sha256sum /etc/nginx/sites-available/other.conf)" = "$other" ]
nginx -t

# Online backup: the writer leaves uncheckpointed committed rows in the WAL.
runuser -u silodev -- python3 - <<'PY'
import os
import sqlite3
import subprocess
from pathlib import Path
db = sqlite3.connect('/data/silo/db/silo-server.db')
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA wal_autocheckpoint=0')
db.execute('INSERT INTO sample VALUES (?)', ('from-wal',))
db.commit()
assert Path('/data/silo/db/silo-server.db-wal').stat().st_size > 0
subprocess.run(['/usr/local/bin/silo-backup'], check=True)
backups = list(Path('/data/silo/backups').glob('silo-*.db'))
assert len(backups) == 1
backup = sqlite3.connect(backups[0])
assert backup.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
assert backup.execute('SELECT value FROM sample ORDER BY rowid').fetchall() == [('preserved',), ('from-wal',)]
assert backups[0].stat().st_mode & 0o777 == 0o600
backup.close()
db.close()
# Missing DB must not create an empty SQLite file or backup.
missing = '/data/silo/db/missing.db'
subprocess.run(['/usr/local/bin/silo-backup'], env=dict(os.environ, DB=missing), check=True)
assert not Path(missing).exists()
assert len(list(Path('/data/silo/backups').glob('silo-*.db'))) == 1
PY
echo 'Provision rerun, nginx rollback, unrelated-site preservation and online SQLite backup passed.'

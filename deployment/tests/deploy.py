"""Run only in the disposable Debian image, after provision.sh's checks.

Real accounts, SQLite backups, symlinks, permissions and tar transfer; Docker,
SSH and HTTPS are stubbed so failure paths cannot affect the shared VPS.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path('/test/deployment')
if not ROOT.is_dir() or os.getuid() != 0:
    raise SystemExit('Run inside deployment/tests/Dockerfile, after the provisioning tests')


class DeployTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boundaries = Path(tempfile.mkdtemp(prefix='silo-boundaries-', dir='/tmp'))
        cls.boundaries.chmod(0o755)
        (cls.boundaries / 'docker').write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
record = {'args': args}
if args[0] == 'login':
    assert sys.stdin.read() == 'test-registry-token'
    config = pathlib.Path(os.environ['DOCKER_CONFIG']) / 'config.json'
    config.write_text('temporary-test-credential')
    record['credential_file'] = str(config)
else:
    assert args[0] == 'compose'
    directory = args[args.index('--project-directory') + 1]
    command = args[args.index('-f') + 2:]
    record.update(directory=directory, command=command)
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps(record) + '\\n')
if args[0] == 'login':
    sys.exit(0)
if command[0] == 'pull' and os.environ.get('FAIL_PULL'):
    sys.exit(1)
if command[0] == 'up':
    pathlib.Path(os.environ['RUNNING']).write_text(directory)
    if os.environ.get('FAIL_UP') and directory != os.environ.get('PREVIOUS'):
        sys.exit(1)
if command[0] == 'stop':
    pathlib.Path(os.environ['RUNNING']).write_text('stopped')
''')
        (cls.boundaries / 'curl').write_text('''#!/usr/bin/env python3
import os, sys
if os.environ.get('FAIL_HTTPS'):
    sys.exit(22)
print('{"status":"ok"}')
''')
        (cls.boundaries / 'sleep').write_text('#!/bin/sh\nexit 0\n')
        (cls.boundaries / 'ssh').write_text('''#!/usr/bin/env python3
import os, subprocess, sys
if os.environ.get('FAIL_SSH'):
    sys.exit(255)
args = sys.argv[1:]
assert 'StrictHostKeyChecking=yes' in args
assert 'IdentitiesOnly=yes' in args
assert '-T' in args
command = args[-1]
assert 'test-registry-token' not in command
assert 'PRIVATE KEY' not in command
# SSH does not forward the runner's secrets or release variables.
env = {k: v for k, v in os.environ.items() if k in (
    'PATH', 'CALL_LOG', 'RUNNING', 'FAIL_PULL', 'FAIL_UP', 'FAIL_HTTPS', 'PREVIOUS')}
sys.exit(subprocess.run(['runuser', '-u', 'silodev', '--', 'env',
    *[f'{k}={v}' for k, v in env.items()], 'bash', '-c', command], env=env).returncode)
''')
        for path in cls.boundaries.iterdir():
            path.chmod(0o755)
        cls.key = cls.boundaries / 'deploy-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(cls.key)], check=True)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='silo-deploy-', dir='/tmp'))
        self.work.chmod(0o777)
        self.log = self.work / 'calls.jsonl'
        self.running = self.work / 'running'
        self.env = dict(PATH=f'{self.boundaries}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                        CALL_LOG=str(self.log), RUNNING=str(self.running))
        for name in ('current', 'previous'):
            Path(f'/opt/silo/{name}').unlink(missing_ok=True)
        self.backup_env = Path('/etc/silo/backup.env').read_text()
        self.addCleanup(Path('/etc/silo/backup.env').write_text, self.backup_env)

    def make_release(self, name):
        directory = Path('/opt/silo/releases') / self.work.name / name
        directory.mkdir(parents=True)
        for filename in ('deploy.sh', 'config.sh'):
            shutil.copy(ROOT / filename, directory)
        # compose content is validated by real Compose in the existing container job.
        shutil.copy(ROOT / 'compose.yaml', directory)
        (directory / '.env').write_text(
            'SSH_HOST=localhost\nRELEASE_VERSION=v0.1.0\nRELEASE_SHA=' + 'a' * 40 + '\n'
            'SERVER_IMAGE=ghcr.io/example/silo/server@sha256:' + 'b' * 64 + '\n'
        )
        (directory / '.env').chmod(0o600)
        subprocess.run(['chown', '-R', 'silodev:silodev', str(directory.parent)], check=True)
        return directory

    def run_release(self, directory):
        return subprocess.run(['runuser', '-u', 'silodev', '--', 'bash', str(directory / 'deploy.sh')],
                              env=self.env, text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def snapshots(self):
        return set(Path('/data/silo/backups').glob('silo-*.db'))

    def seed_previous(self):
        previous = self.make_release('previous')
        Path('/opt/silo/current').symlink_to(previous)
        self.running.write_text(str(previous))
        self.running.chmod(0o666)
        self.env['PREVIOUS'] = str(previous)
        return previous

    def test_first_deploy_backs_up_and_sets_current(self):
        release = self.make_release('first')
        before = self.snapshots()
        result = self.run_release(release)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(Path('/opt/silo/current').resolve(), release)
        self.assertEqual(self.running.read_text(), str(release))
        self.assertEqual(len(self.snapshots() - before), 1)
        self.assertEqual([c['command'][0] for c in self.calls()], ['config', 'pull', 'up', 'ps'])

    def test_successful_update_keeps_previous(self):
        previous = self.seed_previous()
        release = self.make_release('update')
        result = self.run_release(release)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path('/opt/silo/current').resolve(), release)
        self.assertEqual(Path('/opt/silo/previous').resolve(), previous)

    def test_failed_pull_leaves_server_and_database_untouched(self):
        previous = self.seed_previous()
        before = self.snapshots()
        self.env['FAIL_PULL'] = '1'
        result = self.run_release(self.make_release('bad-pull'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(Path('/opt/silo/current').resolve(), previous)
        self.assertEqual(self.running.read_text(), str(previous))
        self.assertEqual(self.snapshots(), before)
        self.assertFalse(any(c['command'][0] == 'up' for c in self.calls()))

    def test_failed_backup_never_replaces_server(self):
        previous = self.seed_previous()
        Path('/etc/silo/backup.env').write_text('KEEP_DAYS=invalid\n')
        result = self.run_release(self.make_release('bad-backup'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.running.read_text(), str(previous))
        self.assertFalse(any(c['command'][0] == 'up' for c in self.calls()))

    def test_unhealthy_replacement_and_https_failure_restart_previous(self):
        previous = self.seed_previous()
        for failure in ('FAIL_UP', 'FAIL_HTTPS'):
            with self.subTest(failure=failure):
                self.env[failure] = '1'
                result = self.run_release(self.make_release(failure.lower()))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(Path('/opt/silo/current').resolve(), previous)
                self.assertEqual(self.running.read_text(), str(previous))
                del self.env[failure]
        # Recovery never rewinds the live database to a snapshot.
        value = subprocess.check_output(['sqlite3', '/data/silo/db/silo-server.db',
                                         'SELECT value FROM sample ORDER BY rowid;'], text=True)
        self.assertEqual(value, 'preserved\nfrom-wal\n')

    def test_failed_first_deploy_stops_failed_container(self):
        self.env['FAIL_UP'] = '1'
        result = self.run_release(self.make_release('bad-first'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path('/opt/silo/current').exists())
        self.assertEqual(self.running.read_text(), 'stopped')

    def test_invalid_image_rejected_before_docker(self):
        release = self.make_release('mutable-tag')
        path = release / '.env'
        path.write_text(path.read_text().replace('@sha256:' + 'b' * 64, ':latest'))
        result = self.run_release(release)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls())

    def test_runner_transfer_and_temporary_credentials(self):
        for failure in ('', 'FAIL_UP'):
            with self.subTest(failure=failure):
                env = dict(self.env, SSH_HOST='203.0.113.10', SSH_PRIVATE_KEY=self.key.read_text(),
                           SSH_KNOWN_HOSTS='203.0.113.10 ' + self.key.with_suffix('.pub').read_text(),
                           GHCR_USER='tester', GHCR_TOKEN='test-registry-token',
                           SERVER_IMAGE='ghcr.io/example/silo/server@sha256:' + 'b' * 64,
                           RELEASE_VERSION='v0.1.0', RELEASE_SHA='a' * 40)
                if failure:
                    env[failure] = '1'
                before = set(Path('/opt/silo/releases').iterdir())
                result = subprocess.run(['bash', str(ROOT / 'deploy-ssh.sh')], env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, not failure, result.stdout + result.stderr)
                added = set(Path('/opt/silo/releases').iterdir()) - before
                self.assertEqual(len(added), 1)
                directory = added.pop()
                self.assertFalse((directory / '.registry').exists())
                self.assertEqual((directory / '.env').stat().st_mode & 0o777, 0o600)
                for filename in ('.env', 'config.sh', 'compose.yaml', 'deploy.sh'):
                    self.assertNotIn('test-registry-token', (directory / filename).read_text())
                self.assertNotIn('test-registry-token', result.stdout + result.stderr)
                self.assertNotIn(self.key.read_text(), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

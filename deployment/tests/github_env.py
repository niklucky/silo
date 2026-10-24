"""Exercise the settings helper with real keys and stubbed GitHub/SSH boundaries."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GithubEnvTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.key = self.work / 'deploy'
        self.host = self.work / 'host'
        for key in (self.key, self.host):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.known = self.work / 'known_hosts'
        self.known.write_text('203.0.113.10 ' + self.host.with_suffix('.pub').read_text())
        self.config = self.work / 'production.env'
        self.config.write_text(
            f'SSH_HOST=203.0.113.10\nSSH_PRIVATE_KEY_PATH={self.key}\n'
            f'SSH_KNOWN_HOSTS_PATH={self.known}\nGITHUB_REPO=example/silo\n'
        )
        self.log = self.work / 'calls.jsonl'
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        gh = self.bin / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
value = sys.stdin.read() if args[:2] == ['secret', 'set'] else None
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps({'args': args, 'stdin': value, 'host': os.environ.get('GH_HOST')}) + '\\n')
if args[0] == 'api':
    if os.environ.get('API_FAIL'):
        sys.exit(1)
    state = pathlib.Path(os.environ['ENV_STATE'])
    if '--method' in args:
        state.touch()
    elif state.exists():
        print('production')
''')
        gh.chmod(0o755)
        ssh = self.bin / 'ssh'
        ssh.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps({'ssh': sys.argv[1:]}) + '\\n')
sys.exit(int(os.environ.get('SSH_FAIL', 0)))
''')
        ssh.chmod(0o755)
        self.env = {
            key: value for key, value in os.environ.items() if key in ('PATH', 'HOME', 'TMPDIR')
        }
        self.env.update(PATH=f'{self.bin}:{os.environ["PATH"]}', CALL_LOG=str(self.log),
                        ENV_STATE=str(self.work / 'environment-exists'), GH_HOST='wrong.example.com')

    def run_helper(self, *args):
        return subprocess.run(
            ['bash', str(ROOT / 'deployment/github-env.sh'), f'--env-file={self.config}', *args],
            cwd=self.work, env=self.env, capture_output=True, text=True,
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def writes(self):
        return [call for call in self.calls() if call.get('args', [''])[0] in ('secret', 'variable')
                or '--method' in call.get('args', [])]

    def test_check_never_mutates(self):
        result = self.run_helper('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.writes())
        self.assertTrue(any('ssh' in call for call in self.calls()))

    def test_upload_and_rerun_preserve_existing_environment(self):
        for _ in range(2):
            result = self.run_helper()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(self.key.read_text(), result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(sum('--method' in call.get('args', []) for call in calls), 1)
        self.assertTrue(all(call['host'] == 'github.com' for call in calls if 'args' in call))
        writes = [call for call in calls if call.get('args', [''])[0] in ('secret', 'variable')]
        self.assertEqual(len(writes), 18)
        for call in writes:
            self.assertIn('example/silo', call['args'])
            self.assertIn('production', call['args'])
            self.assertNotIn(self.key.read_text(), ' '.join(call['args']))
        secrets = {call['args'][2]: call['stdin'] for call in writes if call['args'][0] == 'secret'}
        self.assertEqual(secrets['SSH_PRIVATE_KEY'], self.key.read_text())
        self.assertEqual(secrets['SSH_HOST'], '203.0.113.10')
        self.assertEqual(secrets['SSH_KNOWN_HOSTS'], self.known.read_text())

    def test_hashed_host_with_nonstandard_port(self):
        self.config.write_text(self.config.read_text() + 'SSH_PORT=2222\n')
        self.known.write_text('[203.0.113.10]:2222 ' + self.host.with_suffix('.pub').read_text())
        subprocess.run(['ssh-keygen', '-H', '-f', str(self.known)], check=True, capture_output=True)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        secrets = {call['args'][2]: call['stdin'] for call in self.writes()
                   if call['args'][0] == 'secret'}
        self.assertEqual(secrets['SSH_KNOWN_HOSTS'], self.known.read_text())
        ssh = next(call['ssh'] for call in self.calls() if 'ssh' in call)
        self.assertIn('2222', ssh)
        self.assertIn('StrictHostKeyChecking=yes', ssh)

    def test_preflight_failures_do_not_write(self):
        for name in ('SSH_FAIL', 'API_FAIL'):
            with self.subTest(name=name):
                self.env[name] = '1'
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.writes())
                del self.env[name]

    def test_missing_or_revoked_trust_does_not_write(self):
        for prefix in ('different.example.com ', '@revoked 203.0.113.10 '):
            with self.subTest(prefix=prefix):
                self.known.write_text(prefix + self.host.with_suffix('.pub').read_text())
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.writes())

    def test_invalid_repository_does_not_write(self):
        self.config.write_text(self.config.read_text() + 'GITHUB_REPO=bad/repo;touch marker\n')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.writes())
        self.assertFalse((self.work / 'marker').exists())


if __name__ == '__main__':
    unittest.main()

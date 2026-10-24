"""Literal env parsing and input validation on macOS and CI; no network calls."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ConfigTests(unittest.TestCase):
    def run_config(self, text, command='load_config "$1"; printf "%s" "$DOMAIN"'):
        with tempfile.NamedTemporaryFile(mode='w') as config:
            config.write(text)
            config.flush()
            return subprocess.run(
                ['bash', '-eu', '-c', '. deployment/config.sh; ' + command, 'bash', config.name],
                cwd=ROOT, text=True, capture_output=True,
                env={key: value for key, value in os.environ.items() if key in ('PATH', 'HOME', 'TMPDIR')},
            )

    def test_crlf_quotes_and_last_assignment(self):
        result = self.run_config('SSH_HOST=203.0.113.10\r\nDOMAIN=old.example.com\r\nDOMAIN="silo.warpunit.com"\r\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'silo.warpunit.com')

    def test_values_never_execute_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'executed'
            result = self.run_config(f'VALUE=$(touch {marker})\n', 'env_value "$1" VALUE')
            self.assertEqual(result.stdout, f'$(touch {marker})')
            self.assertFalse(marker.exists())

    def test_invalid_remote_values_rejected(self):
        for setting in ('SSH_HOST=-oProxyCommand=bad', 'DOMAIN=example.com;id', 'SERVER_PORT=0', 'SILO_UID=0', 'SSH_PORT=65536'):
            with self.subTest(setting=setting):
                result = self.run_config('SSH_HOST=203.0.113.10\n' + setting + '\n')
                self.assertNotEqual(result.returncode, 0)

    def test_release_requires_version_commit_and_immutable_image(self):
        valid = ('SSH_HOST=203.0.113.10\nRELEASE_VERSION=v1.2.3\nRELEASE_SHA=' + 'a' * 40 + '\n'
                 'SERVER_IMAGE=ghcr.io/example/silo/server@sha256:' + 'b' * 64 + '\n')
        command = ('load_config "$1"; for name in RELEASE_VERSION RELEASE_SHA SERVER_IMAGE; '
                   'do setting "$name"; done; validate_release')
        result = self.run_config(valid, command)
        self.assertEqual(result.returncode, 0, result.stderr)
        for setting in ('RELEASE_VERSION=v1.2', 'RELEASE_VERSION=v01.2.3',
                        'RELEASE_VERSION=v1.2.3;id', 'RELEASE_SHA=short',
                        'SERVER_IMAGE=ghcr.io/example/silo/server:latest'):
            with self.subTest(setting=setting):
                result = self.run_config(valid + setting + '\n', command)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()

"""Exercise the release installer offline, including a failed replacement install."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


class InstallerTest(unittest.TestCase):
    def test_install_and_checksum_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dest = root / "install dir"
            assets = []
            for platform in ("linux-x64", "macos-arm64", "macos-x64"):
                name = f"silo-{platform}"
                binary = root / name
                binary.write_bytes(name.encode())
                digest = hashlib.sha256(binary.read_bytes()).hexdigest()
                assets.append({"name": name, "state": "uploaded", "digest": f"sha256:{digest}"})
            script = subprocess.check_output(
                [sys.executable, SCRIPTS / "render-cli-installer.py", "niklucky/silo", "v1.2.3"],
                input=json.dumps({"assets": assets}), text=True,
            )
            fake = root / "bin"
            fake.mkdir()
            (fake / "uname").write_text('#!/bin/sh\ncase "$1" in -s) echo "$OS";; -m) echo "$ARCH";; esac\n')
            (fake / "curl").write_text(
                '#!/bin/bash\nset -eu\nurl=${!#}\n'
                '[[ "$url" == https://github.com/niklucky/silo/releases/download/v1.2.3/silo-* ]]\n'
                'while [[ "$1" != "--output" ]]; do shift; done\n'
                'cp "$FIXTURES/${url##*/}" "$2"\n'
            )
            for tool in fake.iterdir():
                tool.chmod(0o755)
            env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", SILO_INSTALL_DIR=str(dest),
                       FIXTURES=str(root))
            for system, arch, platform in (("Linux", "x86_64", "linux-x64"),
                                           ("Darwin", "arm64", "macos-arm64"),
                                           ("Darwin", "x86_64", "macos-x64")):
                env.update(OS=system, ARCH=arch)
                subprocess.run(["bash"], input=script, env=env, text=True, check=True)
                self.assertEqual((dest / "silo").read_text(), f"silo-{platform}")
                self.assertTrue(os.access(dest / "silo", os.X_OK))
            (root / "silo-macos-x64").write_bytes(b"truncated")
            bad = subprocess.run(["bash"], input=script, env=env, text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("SHA-256 verification failed", bad.stderr)
            self.assertEqual((dest / "silo").read_text(), "silo-macos-x64")
            self.assertEqual(list(dest.iterdir()), [dest / "silo"])


if __name__ == "__main__":
    unittest.main()

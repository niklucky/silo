"""Render the installer for the exact binary assets stored on a GitHub release."""
import json
import re
import sys
from pathlib import Path

repository, version = sys.argv[1:]
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
    sys.exit("Invalid repository")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
    sys.exit("Invalid release tag")

assets = {asset["name"]: asset for asset in json.load(sys.stdin)["assets"]}
script = Path(__file__).with_name("install-cli.sh").read_text()
script = script.replace("@REPOSITORY@", repository).replace("@VERSION@", version)
for platform in ("linux-x64", "macos-arm64", "macos-x64"):
    name = f"silo-{platform}"
    asset = assets.get(name, {})
    digest = re.fullmatch(r"sha256:([0-9a-f]{64})", asset.get("digest") or "")
    if asset.get("state") != "uploaded" or not digest:
        sys.exit(f"Missing uploaded binary or SHA-256 digest for {name}")
    script = script.replace("@" + platform.upper().replace("-", "_") + "@", digest[1])
sys.stdout.write(script)

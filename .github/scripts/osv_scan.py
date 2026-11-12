#!/usr/bin/env python3
"""Weekly all-severity scan; verified OSV binary, no SARIF upload or project build."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from urllib.request import urlopen

VERSION = "v2.7.1"
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
# Published release asset digests, verified against GitHub's release metadata.
ASSETS = {
    ("Linux", "x86_64"): ("linux_amd64", "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8"),
    ("Linux", "aarch64"): ("linux_arm64", "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81"),
    ("Darwin", "x86_64"): ("darwin_amd64", "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b"),
    ("Darwin", "arm64"): ("darwin_arm64", "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3"),
}


def scan(root, *, download=urlopen, run=subprocess.run):
    key = (platform.system(), platform.machine())
    if key not in ASSETS:
        raise ValueError("unsupported scanner platform")
    asset, expected = ASSETS[key]
    url = f"https://github.com/google/osv-scanner/releases/download/{VERSION}/osv-scanner_{asset}"
    with tempfile.TemporaryDirectory(prefix="osv-scan-", dir=os.getenv("RUNNER_TEMP") or None) as temporary:
        binary = Path(temporary) / "osv-scanner"
        digest, size = hashlib.sha256(), 0
        with download(url, timeout=60) as response, binary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ValueError("scanner download too large")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("scanner checksum mismatch")
        binary.chmod(0o700)
        # Empty inventories are expected in these Actions-only repositories.
        # Findings and all other scanner failures retain their nonzero status.
        return run([str(binary), "scan", "source", "--recursive", "--allow-no-lockfiles", str(Path(root).resolve())],
                   check=False).returncode


def main():
    try:
        return scan(Path.cwd())
    except Exception as exc:
        print(f"OSV scan failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

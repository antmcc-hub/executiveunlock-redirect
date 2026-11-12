"""No network or scanners: checksum, failure propagation and cleanup fixtures."""
import contextlib
import hashlib
import io
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/osv_scan.py"


class OSVScanTests(unittest.TestCase):
    def setUp(self):
        self.scope = runpy.run_path(str(SCRIPT))["scan"].__globals__
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.payload = b"fixture scanner binary"
        self.scope["ASSETS"] = {("Linux", "x86_64"): ("linux_amd64", hashlib.sha256(self.payload).hexdigest())}
        self.platform = patch.multiple(self.scope["platform"], system=lambda: "Linux", machine=lambda: "x86_64")
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def test_scanner_status_is_preserved_and_private_binary_is_removed(self):
        for status in (0, 1, 2, 128):
            with self.subTest(status=status):
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    binary = Path(argv[0])
                    self.assertEqual(binary.read_bytes(), self.payload)
                    self.assertEqual(binary.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(argv[1:], ["scan", "source", "--recursive", "--allow-no-lockfiles", str(self.root.resolve())])
                    self.assertEqual(kwargs, {"check": False})
                    return subprocess.CompletedProcess(argv, status)
                result = self.scope["scan"](self.root, download=lambda *a, **k: io.BytesIO(self.payload), run=run)
                self.assertEqual(result, status)
                self.assertFalse(Path(calls[0][0]).exists())

    def test_tampered_download_is_never_executed(self):
        run = Mock()
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.scope["scan"](self.root, download=lambda *a, **k: io.BytesIO(b"tampered"), run=run)
        run.assert_not_called()

    def test_failed_download_is_never_executed(self):
        run = Mock()
        with self.assertRaises(OSError):
            self.scope["scan"](self.root, download=Mock(side_effect=OSError("fixture")), run=run)
        run.assert_not_called()

    def test_oversized_download_is_never_executed(self):
        self.scope["MAX_DOWNLOAD_BYTES"] = len(self.payload) - 1
        run = Mock()
        with self.assertRaisesRegex(ValueError, "too large"):
            self.scope["scan"](self.root, download=lambda *a, **k: io.BytesIO(self.payload), run=run)
        run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_execution_removes_verified_binary(self):
        paths = []
        def run(argv, **kwargs):
            paths.append(Path(argv[0]))
            raise OSError("fixture execution failure")
        with self.assertRaises(OSError):
            self.scope["scan"](self.root, download=lambda *a, **k: io.BytesIO(self.payload), run=run)
        self.assertFalse(paths[0].exists())

    def test_unsupported_platform_never_downloads(self):
        self.scope["ASSETS"] = {}
        download = Mock()
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.scope["scan"](self.root, download=download)
        download.assert_not_called()

    def test_entrypoint_fails_without_printing_exception_details(self):
        self.scope["scan"] = Mock(side_effect=ValueError("private fixture detail"))
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(self.scope["main"](), 2)
        self.assertIn("ValueError", error.getvalue())
        self.assertNotIn("private fixture detail", error.getvalue())


if __name__ == "__main__":
    unittest.main()

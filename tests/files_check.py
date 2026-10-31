"""File downloads against mocked transport only; no DSM or credentials."""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import urllib.error

import _env
from nas import backends, files, mcp
from nas.errors import NasError


class Response(io.BytesIO):
    headers = {"Content-Type": "application/octet-stream"}


class Downloads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {
            "NAS_FILE_ALLOWED_SHARES": "Documents,Audit",
            "NAS_FILE_DOWNLOAD_DIR": str(self.root), "NAS_FILE_MAX_BYTES": "10"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.backend = object.__new__(backends.PasswordBackend)
        self.backend._sid = "fake-session"
        self.backend.select_origin = lambda: "https://offline.invalid"
        self.backend._url = lambda path: "https://offline.invalid" + path
        self.backend._open = lambda *args: Response(b"hello")
        self.session = types.SimpleNamespace(
            download_to=self.backend.download_to, close=lambda: None,
            call=lambda *a, **kw: {"ok": True, "data": {"files": [{"size": 5}]}})

    def download(self, path="/Documents/a.txt"):
        return files.file_download(self.session, types.SimpleNamespace(path=path))[1]

    def test_success_and_collisions(self):
        self.assertEqual(self.download()["bytes"], 5)
        target = self.root / "a.txt"
        self.assertEqual(target.read_bytes(), b"hello")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        for path in ("/Documents/a.txt", "/Audit/a.txt"):
            with self.assertRaisesRegex(NasError, "already exists"):
                self.download(path)
            self.assertEqual(target.read_bytes(), b"hello")

    def test_mcp_continues_without_internal_error(self):
        requests = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"name": "file_download", "arguments": {"path": path}}}
                    for i, path in enumerate(("/Documents/a.txt", "/Documents/a.txt",
                                              "/Audit/a.txt", "/Documents/b.txt"))]
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(mcp.serve(io.StringIO("\n".join(map(json.dumps, requests))),
                                      output, lambda: self.session, files_only=True), 0)
        replies = [json.loads(line)["result"] for line in output.getvalue().splitlines()]
        self.assertEqual([r["isError"] for r in replies], [False, True, True, False])
        self.assertEqual(errors.getvalue(), "")
        self.assertIn("already exists", replies[1]["content"][0]["text"])

    def test_stream_limit_cleanup(self):
        # Metadata fits, but the actual response exceeds the limit after writing a block.
        response = Response()
        response.read = unittest.mock.Mock(side_effect=[b"12345", b"678901", b""])
        self.backend._open = lambda *a: response
        with self.assertRaisesRegex(NasError, "exceeds"):
            self.download()
        self.assertFalse((self.root / "a.txt").exists())

    def test_transport_failures(self):
        for error in (urllib.error.URLError("secret-url"), TimeoutError(),
                      http.client.IncompleteRead(b"partial", 20), ConnectionResetError()):
            for after_write in (False, True):
                with self.subTest(error=type(error), after_write=after_write):
                    response = Response()
                    response.read = unittest.mock.Mock(side_effect=[b"part", error] if after_write else [error])
                    self.backend._open = lambda *a: response
                    with self.assertRaises(NasError) as caught:
                        self.download()
                    self.assertNotIn("secret-url", str(caught.exception))
                    self.assertFalse((self.root / "a.txt").exists())
        with patch.object(self.backend, "_open", side_effect=urllib.error.URLError("secret")):
            with self.assertRaises(NasError):
                self.download()

    def test_write_flush_and_close_cleanup(self):
        real_fdopen = os.fdopen
        for failure in ("write", "flush", "close", "write-and-close"):
            class FailingOutput:
                def __init__(self, fd, mode):
                    self.file = real_fdopen(fd, mode)
                def __enter__(self):
                    return self
                def write(self, block):
                    self.file.write(block)
                    if failure in ("write", "write-and-close"):
                        raise OSError("write failed")
                def flush(self):
                    if failure == "flush":
                        raise OSError("flush failed")
                    self.file.flush()
                def __exit__(self, *args):
                    try:
                        self.flush()
                    finally:
                        self.file.close()
                    if failure in ("close", "write-and-close"):
                        raise OSError("close failed")
            with self.subTest(failure=failure), patch.object(backends.os, "fdopen", FailingOutput):
                with self.assertRaises(NasError):
                    self.download()
                self.assertFalse((self.root / "a.txt").exists())

    def test_fdopen_and_directory_errors(self):
        with patch.object(backends.os, "fdopen", side_effect=OSError("failed")):
            with self.assertRaises(NasError):
                self.download()
        self.assertFalse((self.root / "a.txt").exists())
        with patch.object(files.os, "makedirs", side_effect=PermissionError()):
            with self.assertRaisesRegex(NasError, "download directory"):
                self.download()

    def test_guards_and_existing_symlink(self):
        for path in ("/Other/a", "/Documents/../a", "/Documents//a", "/Documents"):
            with self.assertRaises(NasError):
                self.download(path)
        target = self.root / "original"
        target.write_bytes(b"keep")
        (self.root / "a.txt").symlink_to(target)
        with self.assertRaisesRegex(NasError, "already exists"):
            self.download()
        self.assertTrue((self.root / "a.txt").is_symlink())
        self.assertEqual(target.read_bytes(), b"keep")
        os.environ["NAS_FILE_ALLOWED_SHARES"] = ""
        with self.assertRaises(NasError):
            self.download()


if __name__ == "__main__":
    unittest.main()

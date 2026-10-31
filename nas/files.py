"""Opt-in, read-only File Station access for AI agents.

Enable with NAS_FILE_ALLOWED_SHARES (comma-separated DSM share names). This module
never calls File Station's delete, move, rename, write, or upload APIs.
The authenticated DSM account must ALSO have read-only folder permissions.
"""

from __future__ import annotations

import json
import os

from .backends import NasError, describe_error

DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_DOWNLOAD_DIR = "~/.local/share/synology-nas-cli/downloads"


def _allowed_shares() -> set:
    raw = os.environ.get("NAS_FILE_ALLOWED_SHARES", "")
    shares = set()
    for item in raw.split(","):
        name = item.strip()
        if not name:
            continue
        if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
            raise NasError("invalid share in NAS_FILE_ALLOWED_SHARES: expected share names without slashes")
        shares.add(name)
    if not shares:
        raise NasError("file access disabled: set NAS_FILE_ALLOWED_SHARES to explicit DSM share names")
    return shares


def _check_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path or "\x00" in path:
        raise NasError("expected an absolute File Station path, e.g. /Documents/report.pdf")
    pieces = path.split("/")
    if len(pieces) < 2 or any(p in ("", ".", "..") for p in pieces[1:]):
        raise NasError("invalid File Station path: empty, . and .. segments are forbidden")
    if pieces[1] not in _allowed_shares():
        raise NasError("File Station access denied: share is not in NAS_FILE_ALLOWED_SHARES")
    return path


def _result(session, method: str, params: dict) -> dict:
    r = session.call("SYNO.FileStation.List", method, params, version=2)
    if not r.get("ok"):
        raise NasError("SYNO.FileStation.List: " + describe_error("SYNO.FileStation.List", r))
    return r.get("data") or {}


def _max_download_bytes() -> int:
    raw = os.environ.get("NAS_FILE_MAX_BYTES", str(DEFAULT_MAX_BYTES))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise NasError("NAS_FILE_MAX_BYTES must be a positive integer")
    if value < 1:
        raise NasError("NAS_FILE_MAX_BYTES must be a positive integer")
    return value


def file_list(session, args):
    path = _check_path(args.path)
    offset = args.offset
    limit = args.limit
    if not 0 <= offset <= 10000000 or not 1 <= limit <= 200:
        raise NasError("file list requires offset 0..10000000 and limit 1..200")
    data = _result(session, "list", {"folder_path": path, "offset": offset, "limit": limit})
    files = [{"name": f.get("name"), "path": f.get("path"), "isdir": f.get("isdir"),
              "size": f.get("additional", {}).get("size", f.get("size"))}
             for f in data.get("files", [])]
    out = {"path": path, "offset": offset, "limit": limit, "total": data.get("total"), "files": files}
    return [json.dumps(out, ensure_ascii=False, indent=2)], out


def file_download(session, args):
    path = _check_path(args.path)
    if len(path.split("/")) < 3:
        raise NasError("download requires a file path inside an allowed share")
    max_bytes = _max_download_bytes()
    # Validate a single ordinary file before allocating disk space.
    data = _result(session, "getinfo", {"path": json.dumps([path])})
    files = data.get("files") or []
    if len(files) != 1:
        raise NasError("File Station did not return exactly one file")
    info = files[0]
    if info.get("isdir") or info.get("islink") or info.get("additional", {}).get("islink"):
        raise NasError("download requires a regular file (not a directory or symlink)")
    size = info.get("additional", {}).get("size", info.get("size"))
    if size is not None:
        try:
            if int(size) > max_bytes:
                raise NasError("file exceeds NAS_FILE_MAX_BYTES; download refused")
        except (ValueError, TypeError):
            pass  # Streaming download enforces the bound even if DSM omits size.

    root = os.path.abspath(os.path.expanduser(
        os.environ.get("NAS_FILE_DOWNLOAD_DIR", DEFAULT_DOWNLOAD_DIR)))
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise NasError(f"cannot create download directory ({type(exc).__name__})") from exc
    if os.path.islink(root) or not os.path.isdir(root):
        raise NasError("NAS_FILE_DOWNLOAD_DIR must be a real local directory")
    destination = os.path.join(root, path.split("/")[-1])
    # The transport must use O_EXCL (never overwrite), 0600 permissions,
    # and bounded streaming; no NAS-side modification is attempted.
    amount = session.download_to(path, destination, max_bytes=max_bytes)
    out = {"nas_path": path, "local_path": destination, "bytes": amount}
    return [json.dumps(out, ensure_ascii=False, indent=2)], out

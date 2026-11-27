"""Offline content integrity verification; no network or activation authority."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path

_MANIFEST = "manifest.json"
_MAX_MANIFEST = 1024 * 1024
_MAX_ENTRIES = 1024
_CHUNK = 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ContentError(ValueError):
    """Content cannot be admitted as verified."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContentError("duplicate manifest key")
        result[key] = value
    return result


def _open_regular(directory: int, name: str):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ContentError(f"not a regular file: {name}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parse_manifest(raw: bytes):
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ContentError("invalid manifest JSON") from exc
    if type(manifest) is not dict or set(manifest) != {"version", "files"}:
        raise ContentError("invalid manifest fields")
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ContentError("unsupported manifest version")
    entries = manifest["files"]
    if type(entries) is not list or not 1 <= len(entries) <= _MAX_ENTRIES:
        raise ContentError("invalid file count")
    names = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"name", "bytes", "sha256"}:
            raise ContentError("invalid file entry")
        name, size, digest = entry["name"], entry["bytes"], entry["sha256"]
        if (type(name) is not str or not _NAME.fullmatch(name)
                or name == _MANIFEST or name in names):
            raise ContentError("invalid or duplicate file name")
        if type(size) is not int or not 0 <= size <= 2**63 - 1:
            raise ContentError("invalid file size")
        if type(digest) is not str or not _DIGEST.fullmatch(digest):
            raise ContentError("invalid file digest")
        names.add(name)
    return entries


def verify_content(root: Path, trusted_manifest_sha256: str) -> tuple[str, ...]:
    """Verify listed files against an independently trusted manifest digest.

    Linux only. The operator must trust the root path's ancestors and the digest.
    A result describes the bytes read, not a lease on future file contents.
    """
    if type(trusted_manifest_sha256) is not str or not _DIGEST.fullmatch(
        trusted_manifest_sha256
    ):
        raise ContentError("invalid trusted manifest digest")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with _open_regular(directory, _MANIFEST) as stream:
            before = _metadata(os.fstat(stream.fileno()))
            raw = stream.read(_MAX_MANIFEST + 1)
            if len(raw) > _MAX_MANIFEST or before != _metadata(os.fstat(stream.fileno())):
                raise ContentError("oversized or changed manifest")
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), trusted_manifest_sha256):
            raise ContentError("manifest digest mismatch")
        entries = _parse_manifest(raw)
        for entry in entries:
            name, size = entry["name"], entry["bytes"]
            digest = hashlib.sha256()
            with _open_regular(directory, name) as stream:
                before = _metadata(os.fstat(stream.fileno()))
                if before[2] != size:
                    raise ContentError(f"file size mismatch: {name}")
                remaining = size
                while remaining:
                    chunk = stream.read(min(_CHUNK, remaining))
                    if not chunk:
                        raise ContentError(f"file truncated: {name}")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1) or before != _metadata(os.fstat(stream.fileno())):
                    raise ContentError(f"file changed: {name}")
            if not hmac.compare_digest(digest.hexdigest(), entry["sha256"]):
                raise ContentError(f"file digest mismatch: {name}")
        return tuple(entry["name"] for entry in entries)
    finally:
        os.close(directory)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        names = verify_content(args.root, args.manifest_sha256)
    except (ContentError, OSError) as exc:
        # Avoid echoing untrusted filenames or OS error paths to a terminal.
        print(f"FAIL: {exc if isinstance(exc, ContentError) else 'content unavailable'}",
              file=sys.stderr)
        raise SystemExit(1) from None
    print(f"PASS: {len(names)} listed content file(s) verified; no activation performed")


if __name__ == "__main__":
    main()

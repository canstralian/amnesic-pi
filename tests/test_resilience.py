import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from amnesic_pi.resilience import ContentError, verify_content


def digest(data):
    return hashlib.sha256(data).hexdigest()


def entry(name="guide.txt", data=b"offline guide"):
    return {"name": name, "bytes": len(data), "sha256": digest(data)}


def write_manifest(root, entries):
    raw = json.dumps({"version": 1, "files": entries}).encode()
    (root / "manifest.json").write_bytes(raw)
    return digest(raw)


@pytest.fixture
def bundle(tmp_path):
    (tmp_path / "guide.txt").write_bytes(b"offline guide")
    return tmp_path, write_manifest(tmp_path, [entry()])


def test_valid_bundle(bundle):
    root, pin = bundle
    assert verify_content(root, pin) == ("guide.txt",)


def test_empty_file(tmp_path):
    (tmp_path / "empty").touch()
    pin = write_manifest(tmp_path, [entry("empty", b"")])
    assert verify_content(tmp_path, pin) == ("empty",)


def test_wrong_pin(bundle):
    root, _ = bundle
    with pytest.raises(ContentError, match="manifest digest mismatch"):
        verify_content(root, "0" * 64)


def test_manifest_changed(bundle):
    root, pin = bundle
    (root / "manifest.json").write_bytes(b"{}")
    with pytest.raises(ContentError, match="manifest digest mismatch"):
        verify_content(root, pin)


def test_equal_length_tampering(bundle):
    root, pin = bundle
    (root / "guide.txt").write_bytes(b"offline guIde")
    with pytest.raises(ContentError, match="file digest mismatch"):
        verify_content(root, pin)


def test_truncation(bundle):
    root, pin = bundle
    (root / "guide.txt").write_bytes(b"x")
    with pytest.raises(ContentError, match="file size mismatch"):
        verify_content(root, pin)


def test_missing_file(bundle):
    root, pin = bundle
    (root / "guide.txt").unlink()
    with pytest.raises(OSError):
        verify_content(root, pin)


@pytest.mark.parametrize("name", ["../guide.txt", "/etc/passwd", "a/b", "manifest.json", ".."])
def test_invalid_paths(tmp_path, name):
    pin = write_manifest(tmp_path, [entry(name)])
    with pytest.raises(ContentError, match="file name"):
        verify_content(tmp_path, pin)


def test_duplicate_names(tmp_path):
    pin = write_manifest(tmp_path, [entry(), entry()])
    with pytest.raises(ContentError, match="file name"):
        verify_content(tmp_path, pin)


def test_duplicate_json_key(tmp_path):
    raw = b'{"version":1,"version":1,"files":[]}'
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(ContentError, match="invalid manifest JSON"):
        verify_content(tmp_path, digest(raw))


@pytest.mark.parametrize("size", [True, -1, "13", 2**63])
def test_invalid_size(tmp_path, size):
    item = entry()
    item["bytes"] = size
    pin = write_manifest(tmp_path, [item])
    with pytest.raises(ContentError, match="file size"):
        verify_content(tmp_path, pin)


def test_symlink_file(bundle):
    root, pin = bundle
    (root / "guide.txt").rename(root / "actual")
    (root / "guide.txt").symlink_to(root / "actual")
    with pytest.raises(OSError):
        verify_content(root, pin)


def test_symlink_manifest(bundle):
    root, pin = bundle
    (root / "manifest.json").rename(root / "actual")
    (root / "manifest.json").symlink_to(root / "actual")
    with pytest.raises(OSError):
        verify_content(root, pin)


def test_symlink_root(bundle):
    root, pin = bundle
    link = root / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        verify_content(link, pin)


def test_fifo_rejected_without_blocking(bundle):
    root, pin = bundle
    (root / "guide.txt").unlink()
    os.mkfifo(root / "guide.txt")
    with pytest.raises(ContentError, match="not a regular file"):
        verify_content(root, pin)


def test_oversized_manifest(tmp_path):
    raw = b" " * (1024 * 1024 + 1)
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(ContentError, match="oversized"):
        verify_content(tmp_path, digest(raw))


def test_cli_status(bundle):
    root, pin = bundle
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    command = [sys.executable, "-m", "amnesic_pi.resilience", str(root), "--manifest-sha256"]
    good = subprocess.run(command + [pin], env=env, capture_output=True, text=True, timeout=5)
    bad = subprocess.run(command + ["0" * 64], env=env, capture_output=True, text=True, timeout=5)
    assert good.returncode == 0 and "no activation performed" in good.stdout
    assert bad.returncode == 1 and "FAIL" in bad.stderr and not bad.stdout


def test_no_partial_success(bundle):
    root, _ = bundle
    pin = write_manifest(root, [entry(), entry("missing.txt")])
    with pytest.raises(OSError):
        verify_content(root, pin)


def test_unknown_schema(tmp_path):
    raw = b'{"version":2,"files":[]}'
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(ContentError, match="unsupported manifest version"):
        verify_content(tmp_path, digest(raw))


def test_read_only_operation(bundle):
    root, pin = bundle
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    assert verify_content(root, pin) == ("guide.txt",)
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


def test_invalid_digest(tmp_path):
    item = entry()
    item["sha256"] = "not-a-digest"
    pin = write_manifest(tmp_path, [item])
    with pytest.raises(ContentError, match="file digest"):
        verify_content(tmp_path, pin)


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_cli_rejects_blank_root(bundle, value):
    root, pin = bundle
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    command = [sys.executable, "-m", "amnesic_pi.resilience", value, "--manifest-sha256", pin]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert "argument root: path must not be empty" in result.stderr
    assert not result.stdout


def test_cli_accepts_explicit_current_directory(bundle):
    root, pin = bundle
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    command = [sys.executable, "-m", "amnesic_pi.resilience", ".", "--manifest-sha256", pin]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and "no activation performed" in result.stdout

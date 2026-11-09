"""Package updates over Tor, with no egress beyond the Tor SOCKS port.

The policy grants root no uplink authority, so plain `apt` cannot reach a
mirror -- by design. Rather than open a maintenance window with the firewall
down, every network source is rewritten to `tor+https://`, which
apt-transport-tor carries through Tor's loopback SOCKS listener. Loopback is
already permitted; nothing in the policy changes.

The rewrite also upgrades plain http to https, so an exit relay sees a TLS
session to the mirror rather than which packages are being fetched. apt still
verifies every index against the archive keyring either way.

Failure is closed: a source this module did not rewrite -- or one added later --
is attempted directly, finds no egress, and times out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .authority import Check

APT_ROOT = Path("/etc/apt")
PROXY_CONF = "apt.conf.d/50amnesic-pi-tor"
# Outside /etc/apt: apt warns on every run about unknown files in sources.list.d.
BACKUP_DIR = Path("/etc/amnesic-pi/apt-sources.orig")

_NETWORK_URI = re.compile(r"\b(?:tor\+)?https?://")
# One-line format: "deb [options] URI suite components", also deb-src.
_LIST_LINE = re.compile(r"^(\s*deb(?:-src)?\s+(?:\[[^\]]*\]\s+)?)(\S+)(.*)$")
# deb822 format: "URIs: one or more space-separated URIs".
_URIS_FIELD = re.compile(r"^(\s*URIs:\s*)(.*)$", re.IGNORECASE)
# Deb822 (RFC822-style) field folding: a continuation line is any line that
# starts with horizontal whitespace. apt reads a folded value as part of the
# field it continues; a parser that only looks at the "URIs:" line itself
# would miss any URI apt still fetches directly.
_CONTINUATION_LINE = re.compile(r"^[ \t]")


@dataclass(frozen=True)
class SourceFile:
    path: Path
    deb822: bool


def torify_uri(uri: str) -> str:
    """`http(s)://host/...` becomes `tor+https://host/...`; anything else is kept."""
    for scheme in ("tor+https://", "tor+http://", "https://", "http://"):
        if uri.startswith(scheme):
            return "tor+https://" + uri[len(scheme) :]
    return uri


def torify_list(text: str) -> str:
    out = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        match = _LIST_LINE.match(body)
        if match:
            body = match.group(1) + torify_uri(match.group(2)) + match.group(3)
        out.append(body + line[len(line.rstrip("\n")) :])
    return "".join(out)


def torify_deb822(text: str) -> str:
    out = []
    in_uris = False
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        ending = line[len(body) :]
        if body.lstrip().startswith("#"):
            out.append(line)
            continue
        match = _URIS_FIELD.match(body)
        if match:
            uris = " ".join(torify_uri(uri) for uri in match.group(2).split())
            body = match.group(1) + uris
            in_uris = True
        elif in_uris and body.strip() and _CONTINUATION_LINE.match(body):
            leading = body[: len(body) - len(body.lstrip())]
            uris = " ".join(torify_uri(uri) for uri in body.split())
            body = leading + uris
        else:
            in_uris = False
        out.append(body + ending)
    return "".join(out)


def source_files(apt_root: Path) -> list[SourceFile]:
    """Every file apt reads sources from, in both formats apt supports.

    Raspberry Pi OS moved from sources.list to deb822 `.sources` files between
    releases; handling both keeps this from holding on only one of them.
    """
    files: list[SourceFile] = []
    main = apt_root / "sources.list"
    if main.exists():
        files.append(SourceFile(main, deb822=False))
    parts = apt_root / "sources.list.d"
    if parts.is_dir():
        for path in sorted(parts.iterdir()):
            if path.suffix == ".list":
                files.append(SourceFile(path, deb822=False))
            elif path.suffix == ".sources":
                files.append(SourceFile(path, deb822=True))
    return files


def _uris(source: SourceFile, text: str) -> list[str]:
    uris: list[str] = []
    in_uris = False
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if source.deb822:
            match = _URIS_FIELD.match(line)
            if match:
                uris.extend(match.group(2).split())
                in_uris = True
            elif in_uris and line.strip() and _CONTINUATION_LINE.match(line):
                uris.extend(line.split())
            else:
                in_uris = False
        else:
            match = _LIST_LINE.match(line)
            if match:
                uris.append(match.group(2))
    return uris


def _write_atomic(path: Path, text: str) -> None:
    """Write `text` to `path` without a window where it is truncated.

    `Path.write_text` opens its target with truncation before writing a byte;
    if provisioning is interrupted (disk full, process killed) partway through,
    the source file is left shorter than either the old or the new content,
    and the already-made backup does nothing to restore it. Writing to a
    sibling temp file and renaming it into place is a single filesystem
    operation: whichever content wins, the file is never observed half-written.
    """
    tmp = path.with_name(path.name + ".amnesic-pi.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def proxy_conf(socks_port: int) -> str:
    return (
        "// Written by amnesic-pi apt torify. tor+ sources go through Tor's\n"
        "// loopback SOCKS listener; the firewall gives apt no other route.\n"
        f'Acquire::tor::proxy "socks5h://apt-transport-tor@127.0.0.1:{socks_port}";\n'
    )


def torify(apt_root: Path, socks_port: int, backup_dir: Path = BACKUP_DIR) -> list[Check]:
    """Rewrite every source to tor+https and point apt-transport-tor at Tor.

    The first rewrite of each file keeps its original under `backup_dir`, at
    the same path relative to `apt_root`; later runs never overwrite it.
    """
    checks: list[Check] = []
    for source in source_files(apt_root):
        original = source.path.read_text(encoding="utf-8")
        rewritten = (torify_deb822 if source.deb822 else torify_list)(original)
        if rewritten == original:
            checks.append(Check(f"torify {source.path.name}", True, "already tor+https"))
            continue
        backup = backup_dir / source.path.relative_to(apt_root)
        if not backup.exists():
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_text(original, encoding="utf-8")
        _write_atomic(source.path, rewritten)
        checks.append(Check(f"torify {source.path.name}", True, f"rewritten; original at {backup}"))

    conf = apt_root / PROXY_CONF
    conf.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(conf, proxy_conf(socks_port))
    checks.append(Check("apt Tor proxy", True, str(conf)))
    return checks + verify(apt_root, socks_port)


def verify(apt_root: Path, socks_port: int) -> list[Check]:
    """Every network source is tor+, and apt-transport-tor points at Tor."""
    checks: list[Check] = []
    files = source_files(apt_root)
    if not files:
        checks.append(Check("apt sources", False, f"no source files under {apt_root}"))
    for source in files:
        uris = _uris(source, source.path.read_text(encoding="utf-8"))
        direct = [
            uri
            for uri in uris
            if _NETWORK_URI.match(uri) and not uri.startswith("tor+https://")
        ]
        checks.append(
            Check(
                f"{source.path.name} is Tor-only",
                not direct,
                "every network source is tor+" if not direct else "direct: " + ", ".join(direct),
            )
        )
    conf = apt_root / PROXY_CONF
    expected = proxy_conf(socks_port)
    try:
        ok = conf.read_text(encoding="utf-8") == expected
    except FileNotFoundError:
        ok = False
    checks.append(
        Check("apt Tor proxy", ok, f"127.0.0.1:{socks_port}" if ok else f"{conf} missing or stale")
    )
    return checks

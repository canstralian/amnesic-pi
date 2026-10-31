"""apt over Tor: every network source rewritten, nothing left with a direct route.

Fixtures follow both Raspberry Pi OS layouts -- one-line `sources.list` files
and deb822 `.sources` files -- so the rewrite does not hold on only one release.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amnesic_pi import aptsources
from amnesic_pi.aptsources import torify, torify_deb822, torify_list, torify_uri, verify

LEGACY_LIST = """\
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free
# deb-src http://deb.debian.org/debian bookworm main
deb [arch=arm64 signed-by=/usr/share/keyrings/x.gpg] https://example.org/repo stable main
deb file:///srv/local ./
"""

RASPI_LIST = "deb http://archive.raspberrypi.com/debian/ bookworm main\n"

DEB822 = """\
Types: deb
URIs: http://deb.debian.org/debian/ https://mirror.example/debian/
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
"""

# A deb822 stanza with the URIs field folded onto an indented continuation
# line, exactly as apt's own writers and admins hand-editing a .sources file
# may produce. apt reads a folded value as one logical field.
DEB822_FOLDED = """\
Types: deb
URIs: http://deb.debian.org/debian/
 http://second.example/debian/
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
"""


def tree(tmp_path: Path) -> Path:
    apt = tmp_path / "apt"
    (apt / "sources.list.d").mkdir(parents=True)
    (apt / "sources.list").write_text(LEGACY_LIST)
    (apt / "sources.list.d" / "raspi.list").write_text(RASPI_LIST)
    (apt / "sources.list.d" / "debian.sources").write_text(DEB822)
    (apt / "sources.list.d" / "notes.txt").write_text("deb http://ignored.example/ x y\n")
    return apt


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("http://deb.debian.org/debian", "tor+https://deb.debian.org/debian"),
        ("https://deb.debian.org/debian", "tor+https://deb.debian.org/debian"),
        ("tor+http://deb.debian.org/debian", "tor+https://deb.debian.org/debian"),
        ("tor+https://deb.debian.org/debian", "tor+https://deb.debian.org/debian"),
        ("file:///srv/local", "file:///srv/local"),
        ("cdrom:[Debian]/", "cdrom:[Debian]/"),
    ],
)
def test_uri_rewrite(uri: str, expected: str):
    assert torify_uri(uri) == expected


def test_one_line_format_keeps_options_comments_and_local_sources():
    out = torify_list(LEGACY_LIST)
    assert "deb tor+https://deb.debian.org/debian bookworm main contrib" in out
    assert "[arch=arm64 signed-by=/usr/share/keyrings/x.gpg] tor+https://example.org/repo" in out
    assert "# deb-src http://deb.debian.org/debian bookworm main" in out, "comments untouched"
    assert "deb file:///srv/local ./" in out
    assert torify_list(out) == out, "the rewrite is idempotent"


def test_deb822_rewrites_every_uri_in_the_field():
    out = torify_deb822(DEB822)
    assert "URIs: tor+https://deb.debian.org/debian/ tor+https://mirror.example/debian/" in out
    assert "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp" in out


def test_deb822_rewrites_a_uri_folded_onto_a_continuation_line():
    """A URI apt. reads from a folded continuation line must not stay direct.

    `torify_deb822` previously matched only the literal `URIs:` line; a value
    folded onto the next (indented) line was left completely untouched --
    apt still fetches it directly, and the firewall blocks it.
    """
    out = torify_deb822(DEB822_FOLDED)
    assert "URIs: tor+https://deb.debian.org/debian/" in out
    assert " tor+https://second.example/debian/" in out
    assert "http://second.example" not in out
    assert "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp" in out


def test_verify_sees_a_uri_folded_onto_a_continuation_line(tmp_path: Path):
    """`verify` must inspect a folded URI, not only the one on the `URIs:` line."""
    apt = tmp_path / "apt"
    (apt / "sources.list.d").mkdir(parents=True)
    (apt / "sources.list.d" / "folded.sources").write_text(DEB822_FOLDED)
    failed = {c.name: c.detail for c in verify(apt, 9050) if not c.ok}
    assert "folded.sources is Tor-only" in failed
    assert "second.example" in failed["folded.sources is Tor-only"]


def test_torify_leaves_no_direct_source_and_points_apt_at_tor(tmp_path: Path):
    apt = tree(tmp_path)
    checks = torify(apt, 9050, backup_dir=tmp_path / "orig")
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    conf = (apt / aptsources.PROXY_CONF).read_text()
    assert 'socks5h://apt-transport-tor@127.0.0.1:9050' in conf
    assert (tmp_path / "orig" / "sources.list.d" / "raspi.list").read_text() == RASPI_LIST
    assert not list((apt / "sources.list.d").glob("*.orig*")), "no backups where apt reads"


def test_a_second_run_never_overwrites_the_original_backup(tmp_path: Path):
    apt = tree(tmp_path)
    torify(apt, 9050, backup_dir=tmp_path / "orig")
    torify(apt, 9050, backup_dir=tmp_path / "orig")
    assert (tmp_path / "orig" / "sources.list").read_text() == LEGACY_LIST


def test_verify_flags_a_source_added_after_provisioning(tmp_path: Path):
    """A later plain-http source has no route; verify must say so before apt hangs."""
    apt = tree(tmp_path)
    torify(apt, 9050, backup_dir=tmp_path / "orig")
    (apt / "sources.list.d" / "extra.list").write_text("deb http://new.example/debian x main\n")
    failed = [c for c in verify(apt, 9050) if not c.ok]
    assert [c.name for c in failed] == ["extra.list is Tor-only"]
    assert "http://new.example/debian" in failed[0].detail


def test_verify_flags_a_proxy_on_the_wrong_port(tmp_path: Path):
    apt = tree(tmp_path)
    torify(apt, 9050, backup_dir=tmp_path / "orig")
    failed = [c for c in verify(apt, 9150) if not c.ok]
    assert [c.name for c in failed] == ["apt Tor proxy"]


def test_verify_fails_when_there_are_no_sources(tmp_path: Path):
    (tmp_path / "apt").mkdir()
    assert not all(c.ok for c in verify(tmp_path / "apt", 9050))


def test_verify_rejects_a_tor_http_source(tmp_path: Path):
    """`tor+http://` is still cleartext to the exit relay -- not Tor-only.

    `verify` previously excluded anything starting with `tor+`, so a source
    this module never wrote -- hand-edited, or added by something else --
    could sit at `tor+http://` and pass as though it were `tor+https://`,
    exposing every package request's content to the exit relay.
    """
    apt = tmp_path / "apt"
    apt.mkdir()
    (apt / "sources.list").write_text("deb tor+http://deb.debian.org/debian bookworm main\n")
    failed = {c.name: c.detail for c in verify(apt, 9050) if not c.ok}
    assert "sources.list is Tor-only" in failed
    assert "tor+http://deb.debian.org/debian" in failed["sources.list is Tor-only"]


def test_torify_write_failure_leaves_the_original_source_intact(tmp_path: Path, monkeypatch):
    """A write that fails partway must not leave the source file truncated.

    `Path.write_text` truncates its target before writing a byte. If the
    write is interrupted, the file is left shorter than either the old or
    the new content, and the backup this function already made does nothing
    to restore it automatically. Writing the replacement to a sibling temp
    file and renaming it into place means a failure here never touches the
    real path at all.
    """
    apt = tree(tmp_path)
    original = (apt / "sources.list").read_text()
    real_write_text = Path.write_text

    def flaky_write_text(self: Path, *args: object, **kwargs: object) -> int:
        if self.name.endswith(".amnesic-pi.tmp"):
            raise OSError("disk full")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", flaky_write_text)
    with pytest.raises(OSError):
        torify(apt, 9050, backup_dir=tmp_path / "orig")
    assert (apt / "sources.list").read_text() == original

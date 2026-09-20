import re
from pathlib import Path

from amnesic_pi.config import Config
from amnesic_pi.firewall import render

TEMPLATE = Path("network/policy.nft.in").read_text()


def test_render_removes_tokens():
    out = render(TEMPLATE, Config("eth0", "eth1"), 123)
    assert "@UPLINK_IF@" not in out
    assert "@CLIENT_IF@" not in out
    assert "meta skuid 123" in out


def test_base_chains_are_default_drop():
    out = render(TEMPLATE, Config("eth0", "eth1"), 123).lower()
    for chain in ("input", "forward", "output"):
        pattern = (
            rf"chain\s+{chain}\s*\{{\s*"
            rf"type\s+filter\s+hook\s+{chain}\s+priority\s+filter;\s*policy\s+drop;"
        )
        assert re.search(pattern, out) is not None


def test_no_generic_forward_accept():
    out = render(TEMPLATE, Config("eth0", "eth1"), 123).lower()
    start = out.index("chain forward")
    end = out.index("chain output")
    section = out[start:end]
    assert " accept" not in section


def test_only_tor_uid_has_generic_uplink_tcp_accept():
    out = render(TEMPLATE, Config("eth0", "eth1"), 4242)
    assert 'oifname "eth0" meta skuid 4242 meta l4proto tcp accept' in out


def test_client_tcp_is_redirected_not_forwarded():
    out = render(TEMPLATE, Config("eth0", "eth1"), 123)
    assert 'iifname "eth1" meta l4proto tcp redirect to :9040' in out


def test_template_does_not_flush_global_ruleset():
    text = TEMPLATE.lower()
    assert "flush ruleset" not in text
    assert "flush table" not in text

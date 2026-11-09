"""Unit coverage for nftables text parsing helpers, independent of a real kernel.

`chain_rules` is what every exclusivity check in `authority.py` is built from:
if it misreads a rule, every check built on it is misled the same way.
"""

from __future__ import annotations

from amnesic_pi.nft import chain_rules


def test_counter_statement_is_stripped():
    body = (
        "type filter hook output priority 0; policy drop;\n"
        '\toifname "eth0" counter packets 3 bytes 180 accept\n'
    )
    assert chain_rules(body) == ['oifname "eth0" accept']


def test_an_interface_literally_named_counter_is_not_corrupted():
    """`oifname "counter"` is a quoted literal, not the `counter` statement.

    The regex used to strip real counter statements previously matched the
    word `counter` anywhere, quotes or not. An uplink interface that happened
    to be named `counter` would have its own quoted name stripped out of the
    rule text, so it could never match the allowlist entry built from the
    same interface name -- `apply` would then fail verification and run
    lockdown against a policy that was, in fact, correct.
    """
    body = (
        "type filter hook output priority 0; policy drop;\n"
        '\toifname "counter" counter packets 3 bytes 180 accept\n'
    )
    assert chain_rules(body) == ['oifname "counter" accept']


def test_counter_stripping_still_works_next_to_a_quoted_interface():
    body = (
        "type filter hook output priority 0; policy drop;\n"
        '\toifname "counter" meta skuid 42 meta l4proto tcp counter packets 1 bytes 60 accept\n'
    )
    assert chain_rules(body) == ['oifname "counter" meta skuid 42 meta l4proto tcp accept']

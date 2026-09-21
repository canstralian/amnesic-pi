"""Regression coverage for the firewall authority transaction.

The invariant under test is the one the appliance's threat model rests on:
forwarding authority comes into existence only inside a transaction that has
already installed *and* verified the nftables policy, and every failure path
leaves forwarding off.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from fakes import FakeKernel, FakeNft, FakeNic, FakeSysctl

from amnesic_pi.authority import Authority, AuthorityError, Check
from amnesic_pi.config import Config
from amnesic_pi.sysctl import IPV4_FORWARD, IPV6_FORWARD_ALL

TEMPLATE = Path("network/policy.nft.in")
TOR_UID = 4242


@dataclass
class Harness:
    """An Authority wired to fakes, with the fakes kept reachable.

    Authority is frozen, so the doubles live here rather than being stapled
    onto the instance.
    """

    authority: Authority
    nft: FakeNft
    kernel: FakeKernel

    @property
    def forwarding(self) -> dict[str, str | None]:
        return self.authority.sysctl.forwarding_state()

    @property
    def tables(self) -> dict[str, str]:
        return self.nft.tables


def build(tmp_path: Path, nft: FakeNft | None = None, client_appears_at: float = 0.0) -> Harness:
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address="02:00:00:00:00:01"),
            "eth1": FakeNic(address="02:00:00:00:00:02", appears_at=client_appears_at),
        },
    )
    nft = nft or FakeNft()
    authority = Authority(
        config=Config("eth0", "eth1", iface_wait_seconds=1),
        nft=nft.interface(),
        sysctl=FakeSysctl.build(tmp_path / "proc"),
        interfaces=kernel.interfaces(),
        template=TEMPLATE,
        uid=TOR_UID,
    )
    return Harness(authority=authority, nft=nft, kernel=kernel)


# -- the happy path --------------------------------------------------------


def test_apply_installs_policy_then_grants_forwarding(tmp_path: Path):
    harness = build(tmp_path)
    assert harness.forwarding[IPV4_FORWARD] == "0"
    harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "1"
    assert harness.forwarding[IPV6_FORWARD_ALL] == "0"
    assert all(check.ok for check in harness.authority.verify())


def test_apply_is_idempotent(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    harness.authority.apply()
    assert all(check.ok for check in harness.authority.verify())


def test_ipv6_forwarding_is_never_granted(tmp_path: Path):
    """Stage 1 has no IPv6 authority path, so IPv6 forwarding stays off."""
    harness = build(tmp_path)
    harness.authority.apply()
    assert harness.forwarding[IPV6_FORWARD_ALL] == "0"


# -- fail-closed apply -----------------------------------------------------


def test_missing_interface_fails_before_any_policy_is_installed(tmp_path: Path):
    """The client NIC never enumerates. The gate must not proceed without it."""
    harness = build(tmp_path, client_appears_at=9999.0)
    with pytest.raises(AuthorityError, match="topology"):
        harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi" not in harness.tables


def test_rejected_candidate_policy_leaves_forwarding_off(tmp_path: Path):
    nft = FakeNft(fail_check=True)
    harness = build(tmp_path, nft=nft)
    with pytest.raises(AuthorityError, match="validation"):
        harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi" not in harness.tables, "a rejected candidate was installed anyway"


def test_failed_policy_load_leaves_forwarding_off(tmp_path: Path):
    harness = build(tmp_path, nft=FakeNft(fail_load=True))
    with pytest.raises(AuthorityError):
        harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_failed_policy_verification_leaves_forwarding_off(tmp_path: Path):
    """The step the old design got wrong.

    Policy installs, verification fails, and forwarding must still be off --
    with no separate boot-time sysctl able to turn it on regardless.
    """
    harness = build(tmp_path)
    original = harness.authority.verify_policy

    def failing_verify() -> list[Check]:
        return [
            Check("chain forward", False, "policy accept") if check.name == "chain forward"
            else check
            for check in original()
        ]

    object.__setattr__(harness.authority, "verify_policy", failing_verify)
    with pytest.raises(AuthorityError, match="failed verification"):
        harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"


@pytest.mark.parametrize("failure", ["check", "load", "delete"])
def test_partial_apply_cannot_leave_clearnet_forwarding(tmp_path: Path, failure: str):
    """Break the transaction at each nftables stage; forwarding must stay off.

    The `delete` case only arises on a re-apply, when the previous table has to
    be replaced, so that run is primed with a successful apply first.
    """
    harness = build(tmp_path / failure)
    if failure == "delete":
        harness.authority.apply()
        assert harness.forwarding[IPV4_FORWARD] == "1"
    setattr(harness.nft, f"fail_{failure}", True)

    with pytest.raises(AuthorityError):
        harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0", f"forwarding on after {failure} failure"


def test_unrenderable_config_does_not_touch_the_ruleset(tmp_path: Path):
    """A configuration or template error must not flush a known-good ruleset."""
    harness = build(tmp_path)
    harness.authority.apply()
    good = dict(harness.tables)
    good_forwarding = dict(harness.forwarding)

    broken = Authority(
        config=harness.authority.config,
        nft=harness.authority.nft,
        sysctl=harness.authority.sysctl,
        interfaces=harness.authority.interfaces,
        template=tmp_path / "no-such-template.nft.in",
        uid=TOR_UID,
    )
    with pytest.raises(AuthorityError, match="render"):
        broken.apply()
    # The render failed before anything touched the kernel, so the previously
    # good posture is intact rather than torn down.
    assert harness.tables == good
    assert harness.forwarding == good_forwarding


# -- verify is read-only ---------------------------------------------------


def test_verify_does_not_mutate_the_system(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    before_tables = dict(harness.tables)
    before_loads = harness.nft.loads
    before_forwarding = harness.forwarding

    for _ in range(3):
        harness.authority.verify()

    assert harness.tables == before_tables
    assert harness.nft.loads == before_loads
    assert harness.forwarding == before_forwarding


def test_verify_fails_when_the_table_is_gone(tmp_path: Path):
    """The out-of-band mutation case: `nft flush ruleset` behind systemd's back."""
    harness = build(tmp_path)
    harness.authority.apply()
    harness.tables.clear()
    checks = harness.authority.verify()
    assert not all(check.ok for check in checks)
    assert any(check.name == "nft table" and not check.ok for check in checks)


def test_verify_fails_when_forwarding_is_off(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    harness.authority.sysctl.write(IPV4_FORWARD, "0")
    assert not all(check.ok for check in harness.authority.verify())


def test_verify_flags_a_foreign_forwarding_path(tmp_path: Path):
    """A second table granting forwarding is an unauthorized path."""
    harness = build(tmp_path)
    harness.authority.apply()
    harness.tables["ip helpful"] = (  # type: ignore[attr-defined]
        "table ip helpful {\n"
        "  chain fwd { type filter hook forward priority 0; policy accept; }\n"
        "}\n"
    )
    failed = [check for check in harness.authority.verify() if not check.ok]
    assert any("unauthorized forward hook" in check.name for check in failed)


def test_verify_flags_downstream_masquerading(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    harness.tables["ip nat"] = (  # type: ignore[attr-defined]
        "table ip nat {\n"
        "  chain post { type nat hook postrouting priority srcnat; policy accept;\n"
        '    oifname "eth0" masquerade }\n'
        "}\n"
    )
    failed = [check for check in harness.authority.verify() if not check.ok]
    assert any("source NAT" in check.name for check in failed)


def test_verify_checks_chain_priorities(tmp_path: Path):
    """A filter chain at the wrong priority can be pre-empted by another table."""
    harness = build(tmp_path)
    harness.authority.apply()
    tables = harness.tables
    tables["inet amnesic_pi"] = tables["inet amnesic_pi"].replace(
        "hook forward priority filter", "hook forward priority 500"
    )
    failed = [check for check in harness.authority.verify() if not check.ok]
    assert any(check.name == "chain forward" and "priority" in check.detail for check in failed)


# -- lockdown --------------------------------------------------------------


def test_lockdown_disables_forwarding_first(tmp_path: Path):
    """Even when the nftables half fails, forwarding must still end up off."""
    harness = build(tmp_path)
    harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "1"

    harness.nft.fail_load = True
    checks = harness.authority.lockdown()
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert any(not check.ok for check in checks), "an incomplete lockdown must report failure"


def test_lockdown_is_idempotent(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    first = harness.authority.lockdown()
    second = harness.authority.lockdown()
    third = harness.authority.lockdown()
    assert all(check.ok for check in first)
    assert all(check.ok for check in second)
    assert all(check.ok for check in third)
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_lockdown_is_safe_after_a_partial_apply(tmp_path: Path):
    """A second lockdown after apply already ran one must still succeed."""
    harness = build(tmp_path, nft=FakeNft(fail_check=True))
    with pytest.raises(AuthorityError):
        harness.authority.apply()
    checks = harness.authority.lockdown()
    assert all(check.ok for check in checks), [
        (check.name, check.detail) for check in checks if not check.ok
    ]
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_lockdown_installs_a_deny_posture_with_no_accept_verdicts(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    harness.authority.lockdown()
    tables = harness.tables
    assert "inet amnesic_pi" not in tables, "the permissive policy survived lockdown"
    deny = tables["inet amnesic_pi_lockdown"]
    assert "accept" not in deny
    assert deny.count("policy drop") == 3


def test_lockdown_runs_automatically_when_apply_fails(tmp_path: Path):
    """apply() is responsible for its own cleanup; a caller need not remember."""
    harness = build(tmp_path, nft=FakeNft(fail_check=True))
    with pytest.raises(AuthorityError):
        harness.authority.apply()
    tables = harness.tables
    assert "inet amnesic_pi_lockdown" in tables
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_apply_after_lockdown_restores_service(tmp_path: Path):
    """Lockdown must not be a one-way door once the fault is fixed."""
    harness = build(tmp_path)
    harness.authority.lockdown()
    harness.authority.apply()
    tables = harness.tables
    assert "inet amnesic_pi_lockdown" not in tables
    assert harness.forwarding[IPV4_FORWARD] == "1"


# -- lockdown must not depend on configuration ----------------------------


def test_lockdown_needs_no_configuration(tmp_path: Path):
    """The containment path must not share a failure mode with what it contains.

    systemd runs lockdown from OnFailure= and ExecStop=. If a typo in
    network.env is what made the firewall unit fail, a lockdown that parses
    that same file fails for the same reason -- and forwarding stays on.
    """
    from amnesic_pi.authority import lockdown as config_free_lockdown

    harness = build(tmp_path)
    harness.authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "1"

    # No Config anywhere in this call.
    checks = config_free_lockdown(harness.authority.nft, harness.authority.sysctl)
    assert all(check.ok for check in checks), [
        (c.name, c.detail) for c in checks if not c.ok
    ]
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables


def test_lockdown_command_runs_with_an_unparsable_config(tmp_path, monkeypatch):
    """End to end through the CLI: a broken config must not block containment."""
    from amnesic_pi import fw
    from amnesic_pi.nft import Nft

    nft = FakeNft()
    sysctl = FakeSysctl.build(tmp_path / "proc")
    sysctl.write(IPV4_FORWARD, "1")

    monkeypatch.setattr(Nft, "default", staticmethod(nft.interface))
    monkeypatch.setattr(fw, "Sysctl", lambda: sysctl)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    broken = tmp_path / "broken.env"
    broken.write_text("UPLINK_IF=eth0\nNOT_A_KEY=1\n", encoding="utf-8")

    args = fw.build_parser().parse_args(["--config", str(broken), "lockdown"])
    assert args.func(args) == 0, "lockdown refused to run because the config was broken"
    assert sysctl.read(IPV4_FORWARD) == "0"


def test_apply_still_refuses_an_unparsable_config(tmp_path, monkeypatch):
    """apply must still fail on a bad config -- only lockdown is config-free."""
    from amnesic_pi import fw

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    broken = tmp_path / "broken.env"
    broken.write_text("UPLINK_IF=eth0\nNOT_A_KEY=1\n", encoding="utf-8")
    args = fw.build_parser().parse_args(["--config", str(broken), "apply"])
    with pytest.raises(SystemExit):
        args.func(args)


# -- R1: verification must establish EXCLUSIVE egress authority -----------
#
# The defect these cover: `verify` searched the whole output chain for
# `oifname "<uplink>"` and for `skuid <tor>` separately. Both terms are still
# present when an unrestricted grant is added beside the Tor rule, so the
# verifier passed a policy that authorized every local process to reach the
# Internet. Exclusivity cannot be established by looking for terms; it needs
# every rule in the chain accounted for.


def with_template(harness: Harness, text: str, tmp_path: Path) -> Authority:
    candidate = tmp_path / "candidate.nft.in"
    candidate.write_text(text, encoding="utf-8")
    return Authority(
        config=harness.authority.config,
        nft=harness.authority.nft,
        sysctl=harness.authority.sysctl,
        interfaces=harness.authority.interfaces,
        template=candidate,
        uid=TOR_UID,
    )


def failing(checks) -> dict[str, str]:
    return {check.name: check.detail for check in checks if not check.ok}


TOR_GRANT = 'oifname "@UPLINK_IF@" meta skuid @TOR_UID@ meta l4proto tcp accept'


def test_verify_rejects_an_added_unrestricted_egress_grant(tmp_path: Path):
    """The exact candidate from the PR #9 review: a second, UID-less TCP grant.

    Every term the old check looked for is still present -- the Tor rule is
    untouched and the chain is still bound to the uplink. What changed is that
    one more rule now grants the same egress to everything else on the host.
    """
    harness = build(tmp_path)
    broad = TEMPLATE.read_text(encoding="utf-8").replace(
        TOR_GRANT, TOR_GRANT + '\n        oifname "@UPLINK_IF@" meta l4proto tcp accept'
    )
    authority = with_template(harness, broad, tmp_path)

    with pytest.raises(AuthorityError, match="unaccounted egress grant"):
        authority.apply()

    # Fail closed, not just fail loud.
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables


def test_verify_rejects_a_grant_for_a_uid_that_is_not_tor(tmp_path: Path):
    harness = build(tmp_path)
    swapped = TEMPLATE.read_text(encoding="utf-8").replace(
        TOR_GRANT, 'oifname "@UPLINK_IF@" meta skuid 0 meta l4proto tcp accept'
    )
    authority = with_template(harness, swapped, tmp_path)

    with pytest.raises(AuthorityError) as raised:
        authority.apply()
    assert "Tor UID holds the uplink TCP grant" in str(raised.value)
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_verify_rejects_an_egress_grant_for_a_non_tcp_protocol(tmp_path: Path):
    """UDP egress under the Tor UID is not the grant the threat model allows."""
    harness = build(tmp_path)
    widened = TEMPLATE.read_text(encoding="utf-8").replace(
        TOR_GRANT, TOR_GRANT + '\n        oifname "@UPLINK_IF@" meta l4proto udp accept'
    )
    authority = with_template(harness, widened, tmp_path)

    with pytest.raises(AuthorityError, match="unaccounted egress grant"):
        authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_the_shipped_template_carries_only_documented_exceptions(tmp_path: Path):
    """The negative tests above are worthless if the real template fails too."""
    harness = build(tmp_path)
    harness.authority.apply()
    assert failing(harness.authority.verify()) == {}

    # Every exception the output chain is allowed to carry is named, so adding
    # one is a reviewable act rather than an accident.
    assert set(harness.authority.allowed_output_rules().values()) == {
        "loopback",
        "established and related connections",
        "uplink DHCP, broadcast destination",
        "uplink DHCP, unspecified destination",
    }


def test_verify_rejects_a_redirect_with_the_wrong_protocol(tmp_path: Path):
    """The old check found `iifname` and the port in the chain, not in a rule.

    A redirect that sends UDP where TCP was meant leaves both terms present and
    hands client traffic to a port Tor is not listening on for that protocol.
    """
    harness = build(tmp_path)
    wrong = TEMPLATE.read_text(encoding="utf-8").replace(
        'iifname "@CLIENT_IF@" meta l4proto tcp redirect to :@TRANS_PORT@',
        'iifname "@CLIENT_IF@" meta l4proto udp redirect to :@TRANS_PORT@',
    )
    authority = with_template(harness, wrong, tmp_path)

    with pytest.raises(AuthorityError) as raised:
        authority.apply()
    assert "client TCP -> Tor TransPort" in str(raised.value)
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_verify_rejects_a_redirect_bound_to_the_wrong_interface(tmp_path: Path):
    harness = build(tmp_path)
    wrong = TEMPLATE.read_text(encoding="utf-8").replace(
        'iifname "@CLIENT_IF@" meta l4proto tcp redirect to :@TRANS_PORT@',
        'iifname "@UPLINK_IF@" meta l4proto tcp redirect to :@TRANS_PORT@',
    )
    authority = with_template(harness, wrong, tmp_path)

    with pytest.raises(AuthorityError, match="client TCP|unaccounted prerouting"):
        authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_verify_rejects_an_extra_prerouting_rewrite(tmp_path: Path):
    """prerouting has policy accept, so an unlisted rule there is live."""
    harness = build(tmp_path)
    extra = TEMPLATE.read_text(encoding="utf-8").replace(
        'iifname "@CLIENT_IF@" udp dport 53 redirect to :@DNS_PORT@',
        'iifname "@CLIENT_IF@" udp dport 53 redirect to :@DNS_PORT@\n'
        '        iifname "@CLIENT_IF@" tcp dport 443 redirect to :8443',
    )
    authority = with_template(harness, extra, tmp_path)

    with pytest.raises(AuthorityError, match="unaccounted prerouting rule"):
        authority.apply()
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_a_counter_or_comment_does_not_change_rule_recognition(tmp_path: Path):
    """Normalization must not become a way to smuggle a rule past the check."""
    from amnesic_pi.nft import chain_rules

    body = (
        "type filter hook output priority filter; policy drop;\n"
        '  oifname "eth0" meta skuid 4242 meta l4proto tcp counter packets 12 bytes 900 accept\n'
        '  oifname "eth0" meta l4proto tcp accept comment "innocuous"\n'
        "  # a source comment\n"
    )
    assert chain_rules(body) == [
        'oifname "eth0" meta skuid 4242 meta l4proto tcp accept',
        'oifname "eth0" meta l4proto tcp accept',
    ]


# -- R2: a failed containment must not discard the remaining firewall -----
#
# The defect these cover: lockdown deleted the policy table even when the deny
# posture had failed to load, leaving NO table at all. Forwarding was off, but
# forwarding governs the forward hook; it says nothing about traffic local
# processes originate through the output hook.


def test_failed_deny_install_retains_the_existing_policy(tmp_path: Path):
    harness = build(tmp_path)
    harness.authority.apply()
    assert "inet amnesic_pi" in harness.tables

    harness.nft.fail_load = True
    checks = harness.authority.lockdown()

    assert "inet amnesic_pi" in harness.tables, (
        "lockdown discarded the only remaining firewall after failing to install "
        "its replacement"
    )
    assert harness.forwarding[IPV4_FORWARD] == "0"
    # The operator is told containment did not complete, rather than being told
    # a retained policy is a success.
    unmet = failing(checks)
    assert "deny posture installed" in unmet
    assert "retained" in unmet["policy table removed"]


def test_failed_deny_install_never_leaves_an_empty_ruleset(tmp_path: Path):
    """The appliance must never be left with no filtering whatsoever."""
    harness = build(tmp_path, nft=FakeNft(fail_load=True))
    harness.authority.lockdown()
    harness.authority.lockdown()
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_failed_deny_install_is_reported_as_failed(tmp_path: Path):
    from amnesic_pi.authority import lockdown_succeeded

    harness = build(tmp_path, nft=FakeNft(fail_load=True))
    assert not lockdown_succeeded(harness.authority.lockdown())


def test_repeated_lockdown_replaces_the_deny_table_atomically(tmp_path: Path):
    """A delete-then-load would leave an instant with no table at all.

    By the second lockdown the policy table is already gone, so the deny table
    is the only thing standing between the appliance and the kernel's accept
    defaults. Replacing it has to be one transaction.
    """
    harness = build(tmp_path)
    harness.authority.lockdown()
    assert "inet amnesic_pi_lockdown" in harness.tables

    harness.nft.fail_load = True
    harness.authority.lockdown()

    assert "inet amnesic_pi_lockdown" in harness.tables, (
        "the deny posture was removed before its replacement was installed"
    )
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_lockdown_reports_a_failed_forwarding_write_and_a_failed_load(tmp_path: Path):
    """Combined failure: neither failure may be reported as containment."""
    from amnesic_pi.authority import lockdown as config_free_lockdown

    harness = build(tmp_path, nft=FakeNft(fail_load=True))
    root = tmp_path / "unwritable-proc"
    sysctl = FakeSysctl.build(root)
    # A directory where the knob should be. File permissions would not do it:
    # these commands run as root, and root writes through a read-only mode bit.
    knob = root / IPV4_FORWARD
    knob.unlink()
    knob.mkdir()

    checks = config_free_lockdown(harness.authority.nft, sysctl)
    unmet = failing(checks)
    assert "forwarding disabled" in unmet
    assert "deny posture installed" in unmet


# -- R3: the CLI must not claim more than it established ------------------
#
# The defect these cover: `cmd_apply` printed "appliance locked down" for every
# AuthorityError, including the render failure that deliberately leaves the
# previous policy in place and runs no containment at all -- and it discarded
# the result of its own final verification, exiting 0 after printing FAIL.


def cli_apply(monkeypatch, authority, capsys):
    """Run the real cmd_apply against a supplied authority."""
    from amnesic_pi import fw

    monkeypatch.setattr(fw, "require_root", lambda _command: None)
    monkeypatch.setattr(fw, "authority_for", lambda _args: authority)
    code = fw.cmd_apply(argparse.Namespace())
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_apply_cli_does_not_claim_containment_after_a_render_error(
    tmp_path: Path, monkeypatch, capsys
):
    """The known-good policy is preserved on purpose -- and NOT locked down.

    Both halves matter to an operator. Reporting this as containment would say
    the appliance is denying traffic when it is in fact still forwarding under
    the previous policy.
    """
    harness = build(tmp_path)
    harness.authority.apply()
    broken = with_template(harness, "", tmp_path)
    broken = Authority(
        config=broken.config,
        nft=broken.nft,
        sysctl=broken.sysctl,
        interfaces=broken.interfaces,
        template=tmp_path / "no-such-template.nft.in",
        uid=TOR_UID,
    )

    code, _out, err = cli_apply(monkeypatch, broken, capsys)

    assert code == 1
    assert "NOT locked down" in err
    assert "previously installed policy" in err
    # The claim has to match the facts: nothing was torn down.
    assert harness.forwarding[IPV4_FORWARD] == "1"
    assert "inet amnesic_pi" in harness.tables


def test_apply_cli_reports_containment_when_lockdown_ran(
    tmp_path: Path, monkeypatch, capsys
):
    harness = build(tmp_path, nft=FakeNft(fail_check=True))

    code, _out, err = cli_apply(monkeypatch, harness.authority, capsys)

    assert code == 1
    assert "appliance locked down" in err
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_apply_cli_reports_an_incomplete_lockdown_as_incomplete(
    tmp_path: Path, monkeypatch, capsys
):
    """apply failed AND containment failed. That is its own outcome."""
    harness = build(tmp_path, nft=FakeNft(fail_check=True, fail_load=True))

    code, _out, err = cli_apply(monkeypatch, harness.authority, capsys)

    assert code == 1
    assert "lockdown incomplete" in err
    assert "appliance locked down:" not in err


def test_apply_cli_exits_nonzero_when_the_final_verification_fails(
    monkeypatch, capsys
):
    """The final `report(verify())` result must reach the exit code."""

    class Mismatched:
        def apply(self) -> None:
            return None

        def verify(self):
            return [Check("post-grant posture", False, "injected mismatch")]

    code, out, err = cli_apply(monkeypatch, Mismatched(), capsys)

    assert "FAIL" in out
    assert code == 1, "the CLI printed FAIL and reported success"
    assert "failed verification" in err


def test_apply_cli_exits_zero_on_a_verified_apply(tmp_path: Path, monkeypatch, capsys):
    """The negative tests above prove nothing if the good path cannot pass."""
    harness = build(tmp_path)

    code, out, err = cli_apply(monkeypatch, harness.authority, capsys)

    assert code == 0, err
    assert "FAIL" not in out
    assert harness.forwarding[IPV4_FORWARD] == "1"

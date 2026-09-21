"""The firewall authority transaction.

Forwarding authority is granted here and nowhere else. The appliance boots with
every forwarding knob at zero; `apply` turns IPv4 forwarding on only after the
nftables policy has been installed *and* independently verified, and any
failure along the way runs `lockdown` before returning nonzero.

`verify` is strictly read-only. `lockdown` disables forwarding before it
touches nftables, so a cleanup that itself fails still leaves the appliance
unable to forward.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .firewall import FirewallError, render_file, tor_uid
from .netif import InterfaceError, NetworkInterfaces
from .nft import (
    LOCKDOWN_TABLE_NAME,
    TABLE_FAMILY,
    TABLE_NAME,
    Nft,
    NftError,
    chain_body,
    chain_rules,
    forward_hooks,
    nat_postrouting_masquerades,
    parse_chains,
    strip_chain_declaration,
)
from .sysctl import IPV4_FORWARD, IPV6_FORWARD_ALL, IPV6_FORWARD_DEFAULT, Sysctl, SysctlError

DEFAULT_TEMPLATE = Path("/usr/share/amnesic-pi/policy.nft.in")

# The nftables shape the appliance's security claims rest on. `verify` proves
# the live kernel state matches this, not that a file on disk says so.
REQUIRED_CHAINS: dict[str, tuple[str, str, str]] = {
    # chain: (type, hook, policy)
    "prerouting": ("nat", "prerouting", "accept"),
    "input": ("filter", "input", "drop"),
    "forward": ("filter", "forward", "drop"),
    "output": ("filter", "output", "drop"),
}

# Priorities are part of the posture: a filter chain installed at the wrong
# priority can be bypassed by another table hooking earlier.
REQUIRED_PRIORITIES: dict[str, frozenset[str]] = {
    "prerouting": frozenset({"dstnat", "-100"}),
    "input": frozenset({"filter", "0"}),
    "forward": frozenset({"filter", "0"}),
    "output": frozenset({"filter", "0"}),
}

# The minimal unconditional deny posture. It carries no accept verdicts at all,
# including for loopback: lockdown deliberately prefers connectivity loss to a
# residual forwarding path.
LOCKDOWN_RULESET = f"""table {TABLE_FAMILY} {LOCKDOWN_TABLE_NAME} {{
    chain input {{
        type filter hook input priority -300; policy drop;
    }}

    chain forward {{
        type filter hook forward priority -300; policy drop;
    }}

    chain output {{
        type filter hook output priority -300; policy drop;
    }}
}}
"""


# What an apply failure actually left behind. An operator reading "locked down"
# needs it to mean the deny posture is installed -- not merely that something
# went wrong somewhere.
CONTAINMENT_PRESERVED = "prior policy preserved"
CONTAINMENT_LOCKED_DOWN = "lockdown verified"
CONTAINMENT_INCOMPLETE = "lockdown incomplete"


class AuthorityError(RuntimeError):
    """A failure somewhere in the authority transaction.

    `containment` records the resulting network state, so a caller can report
    what is true rather than assuming the worst path ran. It is None when the
    raising site did not establish one; callers must report that as unknown
    rather than as containment.
    """

    def __init__(self, *args: object, containment: str | None = None) -> None:
        super().__init__(*args)
        self.containment = containment


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def lockdown(nft: Nft, sysctl: Sysctl) -> list[Check]:
    """Fail-safe, idempotent teardown. Requires no configuration at all.

    This deliberately takes no Config. Disabling forwarding and installing an
    unconditional deny posture needs nothing from /etc/amnesic-pi/network.env:
    the knobs and the deny ruleset are both constants. Requiring a parseable
    config here would mean a typo in that file defeats the very mechanism meant
    to contain a failure -- the firewall unit would fail on the bad config, and
    OnFailure= would hand the same bad config to lockdown.

    Order matters: forwarding is disabled first, so a later nftables failure
    cannot leave the appliance forwarding clearnet traffic. Safe after a
    partial apply and safe to run repeatedly.
    """
    checks: list[Check] = []

    failed = sysctl.disable_forwarding()
    checks.append(
        Check(
            "forwarding disabled",
            not failed,
            "all forwarding knobs are 0" if not failed else f"could not write: {', '.join(failed)}",
        )
    )

    # The deny posture goes in first. Its chains hook at priority -300, well
    # ahead of the policy table's filter chains, so once it is loaded nothing
    # the policy table permits can still take effect. Removing the policy table
    # first would instead open a window with no table at all, where the
    # kernel's own accept defaults apply.
    #
    # Replacing any earlier deny table is one nft transaction rather than a
    # delete followed by a load. A separate delete opens the same unfiltered
    # window on a repeated lockdown, when the policy table is already gone and
    # the deny table is briefly the only thing standing.
    try:
        replace = (
            f"delete table {TABLE_FAMILY} {LOCKDOWN_TABLE_NAME}\n"
            if nft.table_exists(LOCKDOWN_TABLE_NAME)
            else ""
        )
        result = nft.load(replace + LOCKDOWN_RULESET)
        installed = result.returncode == 0
        detail = "deny posture installed" if installed else (result.stderr or "").strip()
    except NftError as exc:
        installed, detail = False, str(exc)
    checks.append(Check("deny posture installed", installed, detail))

    # Containment before cleanup. The permissive policy table is removed only
    # once the deny posture is actually in place: it denies by default, so
    # discarding it after a failed deny install would leave the appliance with
    # no input, output or forward filtering at all -- strictly worse than the
    # policy that was there. Forwarding is already off either way, but
    # forwarding control says nothing about traffic local processes originate,
    # which the output hook and not the forward hook governs.
    if not installed:
        checks.append(
            Check(
                "policy table removed",
                False,
                f"{TABLE_NAME} retained: the deny posture is not installed, so removing "
                "it would leave no filtering at all",
            )
        )
    else:
        try:
            nft.delete_table(TABLE_NAME)
            removed, removed_detail = True, f"{TABLE_NAME} removed"
        except NftError as exc:
            removed, removed_detail = False, str(exc)
        checks.append(Check("policy table removed", removed, removed_detail))

    checks.extend(forwarding_checks(sysctl, expect_ipv4="0"))
    return checks


def forwarding_checks(sysctl: Sysctl, expect_ipv4: str = "1") -> list[Check]:
    """Read-only forwarding-state checks. Needs no configuration.

    Unreadable state fails a check; it never raises. `lockdown` calls this on
    its way out of a failure, and an exception here would replace the whole
    containment report with a traceback at exactly the moment an operator needs
    to know what the posture actually is. A knob that cannot be read is also not
    a knob that can be called zero.
    """
    checks: list[Check] = []
    try:
        ipv4 = sysctl.read(IPV4_FORWARD)
    except SysctlError as exc:
        checks.append(Check("IPv4 forwarding", False, str(exc)))
    else:
        checks.append(
            Check("IPv4 forwarding", ipv4 == expect_ipv4, f"{ipv4} (expected {expect_ipv4})")
        )
    for knob in (IPV6_FORWARD_ALL, IPV6_FORWARD_DEFAULT):
        try:
            value = sysctl.read(knob)
        except SysctlError as exc:
            checks.append(Check(knob, False, str(exc)))
            continue
        # Absent means IPv6 is compiled out, which satisfies the invariant.
        checks.append(Check(knob, value in {"0", None}, "absent" if value is None else value))
    return checks


@dataclass(frozen=True)
class Authority:
    config: Config
    nft: Nft
    sysctl: Sysctl
    interfaces: NetworkInterfaces
    template: Path = DEFAULT_TEMPLATE
    uid: int | None = None

    @staticmethod
    def default(config: Config, template: Path = DEFAULT_TEMPLATE) -> Authority:
        return Authority(
            config=config,
            nft=Nft.default(),
            sysctl=Sysctl(),
            interfaces=NetworkInterfaces.default(),
            template=template,
        )

    def _tor_uid(self) -> int:
        return self.uid if self.uid is not None else tor_uid(self.config)

    # -- stage 1: topology -------------------------------------------------

    def require_topology(self) -> None:
        """Both role interfaces must exist before any policy is built.

        Interface names are never guessed: a missing interface is a hard
        failure, bounded only by the enumeration retry budget.
        """
        for iface in (self.config.uplink_if, self.config.client_if):
            try:
                self.interfaces.wait_for(iface, timeout=self.config.iface_wait_seconds)
            except InterfaceError as exc:
                raise AuthorityError(f"topology check failed: {exc}") from exc

    # -- apply -------------------------------------------------------------

    def apply(self) -> None:
        """Install policy and grant forwarding, or fail closed.

        Any exception raised out of here has already been through `lockdown`.
        """
        # Render before touching the kernel: a configuration or template error
        # must not disturb a known-good ruleset.
        try:
            rendered = render_file(self.template, self.config, self._tor_uid())
        except (OSError, FirewallError) as exc:
            # Nothing has been touched, so the previously installed policy and
            # the forwarding state are exactly as they were. Deliberate, per
            # AGENTS.md: a parse failure must not flush a known-good ruleset.
            # It also means the appliance is *not* contained -- that is
            # systemd's job via OnFailure=, and the caller must not claim it.
            raise AuthorityError(
                f"cannot render the firewall policy: {exc}",
                containment=CONTAINMENT_PRESERVED,
            ) from exc

        try:
            self.require_topology()

            # Forwarding is off for the whole of the transaction. It is turned
            # on at the end, after verification, and never before.
            failed = self.sysctl.disable_forwarding()
            if failed:
                raise AuthorityError(
                    f"cannot disable forwarding before applying policy: {', '.join(failed)}"
                )

            self._install(rendered)

            failures = [check for check in self.verify_policy() if not check.ok]
            if failures:
                raise AuthorityError(
                    "installed policy failed verification: "
                    + "; ".join(f"{c.name}: {c.detail}" for c in failures)
                )

            # Only now does forwarding authority exist.
            self._grant_forwarding()

            failures = [check for check in self.verify() if not check.ok]
            if failures:
                raise AuthorityError(
                    "post-grant verification failed: "
                    + "; ".join(f"{c.name}: {c.detail}" for c in failures)
                )
        except (AuthorityError, NftError, SysctlError, InterfaceError) as exc:
            cleanup = self.lockdown()
            unmet = [check for check in cleanup if not check.ok]
            message = str(exc)
            if unmet:
                # The apply failed AND the cleanup was incomplete. Say so: an
                # operator needs to know the appliance is in an unproven state.
                message += " [lockdown incomplete: " + "; ".join(
                    f"{c.name}: {c.detail}" for c in unmet
                ) + "]"
            raise AuthorityError(
                message,
                containment=CONTAINMENT_INCOMPLETE if unmet else CONTAINMENT_LOCKED_DOWN,
            ) from exc

    def _install(self, rendered: str) -> None:
        """Replace only our own table, as a single nft transaction.

        The delete is included only when the table exists so first boot does not
        fail on ENOENT. Unrelated tables are never flushed -- a parse failure
        here must not take down a known-good ruleset someone else installed.
        """
        present = self.nft.table_exists(TABLE_NAME)
        transaction = (
            f"delete table {TABLE_FAMILY} {TABLE_NAME}\n" if present else ""
        ) + rendered

        check = self.nft.check(transaction)
        if check.returncode != 0:
            raise AuthorityError(
                "candidate nftables policy failed validation; existing ruleset untouched: "
                f"{(check.stderr or '').strip()}"
            )
        loaded = self.nft.load(transaction)
        if loaded.returncode != 0:
            raise AuthorityError(
                f"nftables policy load failed: {(loaded.stderr or '').strip()}"
            )
        # A successful apply supersedes any prior lockdown posture; leaving the
        # lockdown table in place would drop the traffic this policy permits.
        self.nft.delete_table(LOCKDOWN_TABLE_NAME)

    def _grant_forwarding(self) -> None:
        try:
            self.sysctl.write(IPV4_FORWARD, "1")
            # Stage 1 has no IPv6 authority path; IPv6 forwarding stays off.
            self.sysctl.write(IPV6_FORWARD_ALL, "0")
            self.sysctl.write(IPV6_FORWARD_DEFAULT, "0")
        except SysctlError as exc:
            raise AuthorityError(f"cannot set the post-verification forwarding state: {exc}") from exc

    # -- verify (read-only) -----------------------------------------------

    def verify_policy(self) -> list[Check]:
        """Read-only checks over the installed nftables policy alone."""
        checks: list[Check] = []
        try:
            listing = self.nft.list_table(TABLE_NAME)
        except NftError as exc:
            return [Check("nft table", False, str(exc))]
        checks.append(Check("nft table", True, f"{TABLE_FAMILY} {TABLE_NAME} present"))

        chains = parse_chains(listing)
        for name, (ctype, hook, policy) in REQUIRED_CHAINS.items():
            chain = chains.get(name)
            if chain is None:
                checks.append(Check(f"chain {name}", False, "missing"))
                continue
            problems = []
            if chain.type != ctype:
                problems.append(f"type={chain.type} expected {ctype}")
            if chain.hook != hook:
                problems.append(f"hook={chain.hook} expected {hook}")
            if chain.policy != policy:
                problems.append(f"policy={chain.policy} expected {policy}")
            if chain.priority not in REQUIRED_PRIORITIES[name]:
                problems.append(
                    f"priority={chain.priority} expected one of "
                    f"{sorted(REQUIRED_PRIORITIES[name])}"
                )
            checks.append(
                Check(
                    f"chain {name}",
                    not problems,
                    "; ".join(problems) if problems else f"{chain.type}/{chain.hook}/{chain.policy}",
                )
            )

        # The forward chain must carry no accept verdict at all. Stage 1 is a
        # transparent proxy: downstream traffic is redirected, never routed.
        try:
            forward = strip_chain_declaration(chain_body(listing, "forward"))
            has_accept = "accept" in forward
            checks.append(
                Check(
                    "forward chain has no accept",
                    not has_accept,
                    "no accept verdict" if not has_accept else "accept verdict present",
                )
            )
        except NftError as exc:
            checks.append(Check("forward chain has no accept", False, str(exc)))

        checks.extend(self._redirect_checks(listing))
        checks.extend(self._egress_checks(listing))
        checks.extend(self._ruleset_wide_checks())
        return checks

    def allowed_output_rules(self) -> dict[str, str]:
        """Every non-Tor rule the output chain may carry: rule text -> purpose.

        Exclusivity is the security claim, so the exceptions are enumerated
        here rather than left implicit. Adding one is a deliberate act with a
        reviewable diff; anything not listed is an unaccounted egress grant.
        """
        uplink = self.config.uplink_if
        return {
            'oifname "lo" accept': "loopback",
            "ct state established,related accept": "established and related connections",
            f'oifname "{uplink}" udp sport 68 udp dport 67 ip daddr 255.255.255.255 accept': (
                "uplink DHCP, broadcast destination"
            ),
            f'oifname "{uplink}" udp sport 68 udp dport 67 ip daddr 0.0.0.0 accept': (
                "uplink DHCP, unspecified destination"
            ),
        }

    def tor_egress_rule(self, uid: int) -> str:
        """The one rule that grants normal Internet egress, as a whole predicate."""
        return f'oifname "{self.config.uplink_if}" meta skuid {uid} meta l4proto tcp accept'

    def client_redirect_rules(self) -> dict[str, str]:
        """Every rule the prerouting chain may carry: rule text -> check name."""
        client = self.config.client_if
        return {
            f'iifname "{client}" udp dport 53 redirect to :{self.config.dns_port}': (
                f"client DNS -> Tor DNSPort {self.config.dns_port}"
            ),
            f'iifname "{client}" meta l4proto tcp redirect to :{self.config.trans_port}': (
                f"client TCP -> Tor TransPort {self.config.trans_port}"
            ),
        }

    def _redirect_checks(self, listing: str) -> list[Check]:
        """Prove each redirect exists as one whole rule, and nothing else does.

        The interface, the protocol and the destination port have to belong to
        the *same* rule. Searching a whole chain for each term separately is
        satisfied by a chain that redirects the wrong protocol next to a rule
        naming the right port -- client traffic would then be handed somewhere
        Tor is not listening, with every term still present.

        The prerouting chain has policy accept, so an unlisted rule there is a
        live rewrite of client traffic: a dnat elsewhere, or a redirect to a
        port nothing anonymous is bound to.
        """
        try:
            rules = chain_rules(chain_body(listing, "prerouting"))
        except NftError as exc:
            return [Check("client redirects", False, str(exc))]

        required = self.client_redirect_rules()
        checks = [
            Check(name, rule in rules, rule if rule in rules else f"no rule: {rule}")
            for rule, name in required.items()
        ]
        unaccounted = [rule for rule in rules if rule not in required]
        checks.append(
            Check(
                "no unaccounted prerouting rule",
                not unaccounted,
                "only the client redirects" if not unaccounted else "; ".join(unaccounted),
            )
        )
        return checks

    def _egress_checks(self, listing: str) -> list[Check]:
        """Prove the Tor UID is the *only* normal egress principal.

        Every rule in the output chain is accounted for against a named
        exception. Finding `oifname "<uplink>"` and `skuid <tor>` somewhere in
        the chain says nothing about exclusivity: an added
        `oifname "<uplink>" meta l4proto tcp accept` satisfies both searches
        while granting every local process unrestricted TCP egress.
        """
        try:
            rules = chain_rules(chain_body(listing, "output"))
        except NftError as exc:
            return [Check("Tor UID holds the uplink TCP grant", False, str(exc))]
        try:
            uid = self._tor_uid()
        except FirewallError as exc:
            return [Check("Tor UID holds the uplink TCP grant", False, str(exc))]

        tor_rule = self.tor_egress_rule(uid)
        allowed = dict(self.allowed_output_rules())
        allowed[tor_rule] = "Tor uplink TCP egress"

        granted = tor_rule in rules
        unaccounted = [rule for rule in rules if rule not in allowed]
        return [
            Check(
                "Tor UID holds the uplink TCP grant",
                granted,
                tor_rule
                if granted
                else f"no complete rule granting uid {uid} TCP egress via "
                f"{self.config.uplink_if}",
            ),
            Check(
                "no unaccounted egress grant",
                not unaccounted,
                "the output chain carries only the documented exceptions"
                if not unaccounted
                else "; ".join(unaccounted),
            ),
        ]

    def _ruleset_wide_checks(self) -> list[Check]:
        """Look past our own table for a forwarding path somebody else installed."""
        try:
            ruleset = self.nft.list_ruleset()
        except NftError as exc:
            return [Check("no unauthorized forwarding path", False, str(exc))]

        offenders = [
            hook
            for hook in forward_hooks(ruleset)
            if hook.table != f"{TABLE_FAMILY} {TABLE_NAME}"
            and (hook.policy != "drop" or hook.accepts)
        ]
        masquerade = nat_postrouting_masquerades(ruleset)
        return [
            Check(
                "no unauthorized forward hook",
                not offenders,
                "none"
                if not offenders
                else "; ".join(
                    f"{h.table} chain {h.chain} policy {h.policy} accepts={h.accepts}"
                    for h in offenders
                ),
            ),
            Check(
                "no source NAT of downstream traffic",
                not masquerade,
                "none" if not masquerade else ", ".join(masquerade),
            ),
        ]

    def verify_forwarding(self, expect_ipv4: str = "1") -> list[Check]:
        """Read-only forwarding-state checks."""
        return forwarding_checks(self.sysctl, expect_ipv4)

    def verify(self, expect_ipv4_forwarding: str = "1") -> list[Check]:
        """Full read-only posture check: policy plus forwarding state."""
        return self.verify_policy() + self.verify_forwarding(expect_ipv4_forwarding)

    # -- lockdown ----------------------------------------------------------

    def lockdown(self) -> list[Check]:
        """Fail-safe, idempotent teardown; see the module-level `lockdown`.

        Delegates so that the teardown path is identical whether or not a
        Config could be loaded.
        """
        return lockdown(self.nft, self.sysctl)


def lockdown_succeeded(checks: Sequence[Check]) -> bool:
    return all(check.ok for check in checks)

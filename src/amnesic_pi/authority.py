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


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


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
            raise AuthorityError(f"cannot render the firewall policy: {exc}") from exc

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
            raise AuthorityError(message) from exc

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

    def _redirect_checks(self, listing: str) -> list[Check]:
        client = self.config.client_if
        try:
            body = chain_body(listing, "prerouting")
        except NftError as exc:
            return [Check("client redirects", False, str(exc))]
        expectations = (
            (
                f"client DNS -> Tor DNSPort {self.config.dns_port}",
                f'iifname "{client}"' in body
                and "udp dport 53" in body
                and f"redirect to :{self.config.dns_port}" in body,
            ),
            (
                f"client TCP -> Tor TransPort {self.config.trans_port}",
                f'iifname "{client}"' in body
                and f"redirect to :{self.config.trans_port}" in body,
            ),
        )
        return [Check(name, ok, "present" if ok else "missing") for name, ok in expectations]

    def _egress_checks(self, listing: str) -> list[Check]:
        try:
            body = strip_chain_declaration(chain_body(listing, "output"))
        except NftError as exc:
            return [Check("Tor is the only uplink TCP principal", False, str(exc))]
        try:
            uid = self._tor_uid()
        except FirewallError as exc:
            return [Check("Tor UID holds the uplink TCP grant", False, str(exc))]
        bound_to_uplink = f'oifname "{self.config.uplink_if}"' in body
        tor_rule = f"skuid {uid}" in body
        return [
            Check(
                "output chain bound to the uplink interface",
                bound_to_uplink,
                self.config.uplink_if if bound_to_uplink else "no uplink-bound rule",
            ),
            Check(
                "Tor UID holds the uplink TCP grant",
                tor_rule,
                f"skuid {uid}" if tor_rule else f"no rule for uid {uid}",
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
        checks: list[Check] = []
        ipv4 = self.sysctl.read(IPV4_FORWARD)
        checks.append(
            Check("IPv4 forwarding", ipv4 == expect_ipv4, f"{ipv4} (expected {expect_ipv4})")
        )
        for knob in (IPV6_FORWARD_ALL, IPV6_FORWARD_DEFAULT):
            value = self.sysctl.read(knob)
            # Absent means IPv6 is compiled out, which satisfies the invariant.
            ok = value in {"0", None}
            checks.append(Check(knob, ok, "absent" if value is None else value))
        return checks

    def verify(self, expect_ipv4_forwarding: str = "1") -> list[Check]:
        """Full read-only posture check: policy plus forwarding state."""
        return self.verify_policy() + self.verify_forwarding(expect_ipv4_forwarding)

    # -- lockdown ----------------------------------------------------------

    def lockdown(self) -> list[Check]:
        """Fail-safe, idempotent teardown.

        Order matters: forwarding is disabled first, so that a later nftables
        failure cannot leave the appliance forwarding clearnet traffic. Safe
        after a partial apply and safe to run repeatedly.
        """
        checks: list[Check] = []

        failed = self.sysctl.disable_forwarding()
        checks.append(
            Check(
                "forwarding disabled",
                not failed,
                "all forwarding knobs are 0" if not failed else f"could not write: {', '.join(failed)}",
            )
        )

        # The deny posture goes in first. Its chains hook at priority -300, well
        # ahead of the policy table's filter chains, so once it is loaded
        # nothing the policy table permits can still take effect. Removing the
        # policy table first would instead open a window with no table at all,
        # where the kernel's own accept defaults apply.
        try:
            self.nft.delete_table(LOCKDOWN_TABLE_NAME)
            result = self.nft.load(LOCKDOWN_RULESET)
            installed = result.returncode == 0
            detail = "deny posture installed" if installed else (result.stderr or "").strip()
        except NftError as exc:
            installed, detail = False, str(exc)
        checks.append(Check("deny posture installed", installed, detail))

        try:
            self.nft.delete_table(TABLE_NAME)
            removed, removed_detail = True, f"{TABLE_NAME} removed"
        except NftError as exc:
            removed, removed_detail = False, str(exc)
        checks.append(Check("policy table removed", removed, removed_detail))

        checks.extend(self.verify_forwarding(expect_ipv4="0"))
        return checks


def lockdown_succeeded(checks: Sequence[Check]) -> bool:
    return all(check.ok for check in checks)

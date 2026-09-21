"""nftables invocation and read-only inspection of the live ruleset."""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .netif import Runner

TABLE_FAMILY = "inet"
TABLE_NAME = "amnesic_pi"
LOCKDOWN_TABLE_NAME = "amnesic_pi_lockdown"

# "type filter hook forward priority filter; policy drop;"
_CHAIN_RE = re.compile(
    r"chain\s+(?P<name>\S+)\s*\{\s*"
    r"type\s+(?P<type>\S+)\s+hook\s+(?P<hook>\S+)\s+"
    r"(?:device\s+\S+\s+)?priority\s+(?P<priority>[^;]+);\s*"
    r"policy\s+(?P<policy>\w+)\s*;",
)

# The base-chain header on its own, matched inside an already-extracted body.
_CHAIN_DECL_RE = re.compile(
    r"type\s+\S+\s+hook\s+\S+\s+(?:device\s+\S+\s+)?priority\s+[^;]+;\s*policy\s+\w+\s*;",
)


class NftError(RuntimeError):
    pass


@dataclass(frozen=True)
class Chain:
    name: str
    type: str
    hook: str
    priority: str
    policy: str


@dataclass(frozen=True)
class Nft:
    """Thin wrapper over the nft binary.

    `list_*` methods are strictly read-only; they are what `verify` is built
    from, and `verify` must never mutate the system.
    """

    runner: Runner

    @staticmethod
    def default() -> Nft:
        return Nft(runner=Runner.default())

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.runner.run(["nft", *args])

    # -- read-only ---------------------------------------------------------

    def table_exists(self, name: str = TABLE_NAME) -> bool:
        return self._run("list", "table", TABLE_FAMILY, name).returncode == 0

    def list_table(self, name: str = TABLE_NAME) -> str:
        result = self._run("list", "table", TABLE_FAMILY, name)
        if result.returncode != 0:
            raise NftError(
                f"nftables table {TABLE_FAMILY} {name} is not present: "
                f"{(result.stderr or '').strip()}"
            )
        return result.stdout or ""

    def list_ruleset(self) -> str:
        result = self._run("list", "ruleset")
        if result.returncode != 0:
            raise NftError(f"cannot list the nftables ruleset: {(result.stderr or '').strip()}")
        return result.stdout or ""

    # -- mutation ----------------------------------------------------------

    def check(self, ruleset: str) -> subprocess.CompletedProcess[str]:
        """Validate a candidate ruleset without installing it (`nft -c`)."""
        return self._with_temp_file(ruleset, "-c")

    def load(self, ruleset: str) -> subprocess.CompletedProcess[str]:
        """Install a ruleset. nft applies the whole file as one transaction."""
        return self._with_temp_file(ruleset)

    def delete_table(self, name: str = TABLE_NAME) -> None:
        if self.table_exists(name):
            result = self._run("delete", "table", TABLE_FAMILY, name)
            if result.returncode != 0:
                raise NftError(
                    f"cannot delete table {TABLE_FAMILY} {name}: {(result.stderr or '').strip()}"
                )

    def _with_temp_file(self, ruleset: str, *flags: str) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(
            "w", prefix="amnesic-pi-", suffix=".nft", delete=False
        ) as handle:
            handle.write(ruleset)
            candidate = Path(handle.name)
        try:
            return self.runner.run(["nft", *flags, "-f", str(candidate)])
        finally:
            candidate.unlink(missing_ok=True)


def parse_chains(listing: str) -> dict[str, Chain]:
    """Extract base-chain declarations from `nft list` output."""
    chains: dict[str, Chain] = {}
    for match in _CHAIN_RE.finditer(listing):
        chains[match.group("name")] = Chain(
            name=match.group("name"),
            type=match.group("type"),
            hook=match.group("hook"),
            priority=match.group("priority").strip(),
            policy=match.group("policy").lower(),
        )
    return chains


def chain_body(listing: str, chain: str) -> str:
    """Return the text of one chain block, brace-balanced rather than length-capped."""
    marker = re.search(rf"chain\s+{re.escape(chain)}\s*\{{", listing)
    if not marker:
        raise NftError(f"chain {chain!r} is not present in the listing")
    depth = 0
    start = marker.end() - 1
    for index in range(start, len(listing)):
        if listing[index] == "{":
            depth += 1
        elif listing[index] == "}":
            depth -= 1
            if depth == 0:
                return listing[start + 1 : index]
    raise NftError(f"chain {chain!r} is not brace-balanced in the listing")


def strip_chain_declaration(body: str) -> str:
    """Drop a base chain's `type ... policy X;` header, leaving only its rules.

    Counting verdicts in a chain must not be confused by the word `accept` in
    the chain's own default-policy declaration.
    """
    match = _CHAIN_DECL_RE.search(body)
    return body[match.end() :] if match else body


def split_tables(ruleset: str) -> dict[str, str]:
    """Split `nft list ruleset` output into {"family name": body} blocks."""
    tables: dict[str, str] = {}
    for match in re.finditer(r"table\s+(?P<family>\w+)\s+(?P<name>\S+)\s*\{", ruleset):
        depth = 0
        start = match.end() - 1
        for index in range(start, len(ruleset)):
            if ruleset[index] == "{":
                depth += 1
            elif ruleset[index] == "}":
                depth -= 1
                if depth == 0:
                    key = f"{match.group('family')} {match.group('name')}"
                    tables[key] = ruleset[start + 1 : index]
                    break
    return tables


@dataclass(frozen=True)
class ForwardHook:
    table: str
    chain: str
    policy: str
    accepts: int


def forward_hooks(ruleset: str) -> list[ForwardHook]:
    """Every base chain in the whole ruleset that hooks `forward`.

    Used to catch a second table quietly granting forwarding authority that the
    Amnesic Pi table has nothing to do with. `accepts` counts accept verdicts
    inside the chain body, so a default-drop chain with a blanket accept rule
    is still visible as a forwarding path.
    """
    found: list[ForwardHook] = []
    for table, body in split_tables(ruleset).items():
        for match in _CHAIN_RE.finditer(body):
            if match.group("hook") != "forward":
                continue
            name = match.group("name")
            body_text = strip_chain_declaration(chain_body(body, name))
            accepts = len(re.findall(r"(?<![\w-])accept(?![\w-])", body_text))
            found.append(
                ForwardHook(
                    table=table,
                    chain=name,
                    policy=match.group("policy").lower(),
                    accepts=accepts,
                )
            )
    return found


def nat_postrouting_masquerades(ruleset: str) -> list[str]:
    """Tables carrying a masquerade/snat verdict.

    Stage 1 is a transparent proxy, not a router: any source NAT of downstream
    traffic onto the uplink would be an unauthorized forwarding path.
    """
    offenders: list[str] = []
    for table, body in split_tables(ruleset).items():
        if re.search(r"(?<![\w-])(masquerade|snat)(?![\w-])", body):
            offenders.append(table)
    return offenders


# A counter is a statement, not a predicate, and nft renders it with live
# packet/byte totals. Dropping it keeps rule recognition independent of traffic.
_COUNTER_RE = re.compile(r"(?<![\w-])counter(\s+packets\s+\d+\s+bytes\s+\d+)?(?![\w-])")

# An nft-rendered `comment "..."` annotation, likewise not a predicate.
_RULE_COMMENT_RE = re.compile(r'(?<![\w-])comment\s+"(?:[^"\\]|\\.)*"')


def chain_rules(body: str) -> list[str]:
    """Split a chain body into one normalized rule per entry.

    `nft list` prints exactly one rule per line. Reading rules individually is
    what makes exclusivity checkable: a substring search over a whole chain
    cannot tell `oifname "eth0" meta skuid 42 meta l4proto tcp accept` from the
    same terms spread over an unrestricted grant and a separate Tor rule.

    Counters, comments and whitespace are normalized away so that none of them
    changes whether a rule is recognised. Anything left that is not an
    allowed rule is, by construction, an unaccounted grant.
    """
    rules: list[str] = []
    for line in strip_chain_declaration(body).splitlines():
        text = line.split("#", 1)[0]
        text = _RULE_COMMENT_RE.sub(" ", text)
        text = _COUNTER_RE.sub(" ", text)
        text = " ".join(text.split())
        if text and text not in {"{", "}"}:
            rules.append(text)
    return rules

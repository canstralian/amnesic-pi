---
name: nft-policy-audit
description: Audit an nftables ruleset for default-ACCEPT, IPv6 bypasses, DNS bypasses, and output-chain exceptions. Use before signing POLICY_CLEAN, or whenever network/policy.nft.in is edited.
---

# nft-policy-audit (T3 · policy)

Bounded task: audit a ruleset and return findings with line citations.

## Checklist, in order

1. **Default policy.** Every chain — `input`, `forward`, `output` — declares
   `policy drop`. A chain with no explicit policy is a finding.
2. **Output exceptions.** Enumerate every `accept` in the output chain. Each
   must be attributable to a named principal (Tor's UID). An `accept` matched by
   port, executable name, or interface alone is a finding.
3. **IPv6.** No `ip6` or `inet`-family rule creates a forwarding path. IPv6 must
   remain disabled, not merely unrouted.
4. **DNS.** UDP/53 from the client interface redirects to Tor's DNSPort. Any
   path where a client resolver reaches the uplink directly is a finding.
5. **UDP.** Non-53 downstream UDP, QUIC included, is dropped — not accepted, not
   unmatched-and-defaulted if the chain policy were ever changed.
6. **Failure direction.** For each rule, ask: if this rule failed to load, is the
   result more or less permissive? Any rule whose absence opens a path is a finding.

## Verification

Run `nft -c -f <rendered>` and quote the result. A syntax-valid ruleset is not a
correct one — the checklist above still applies.

## Output

Findings as `file:line — what — why it matters`, most severe first. If clean, say
so and list which of the six checks you ran.

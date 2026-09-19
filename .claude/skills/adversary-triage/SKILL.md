---
name: adversary-triage
description: Classify a claimed adversary capability against what Amnesic Pi actually defends. Use when asked "does this protect against X", when evaluating a threat report, or before accepting a feature request framed as a security need.
---

# adversary-triage (T3 · threat-research)

Bounded task: one capability in, one classification out.

## Classifications

| Verdict | Meaning |
|---|---|
| `in-scope-addressed` | The appliance defends this; name the control and the file |
| `in-scope-unaddressed` | It should defend this and does not; this is a finding |
| `out-of-scope-declared` | THREAT-MODEL.md explicitly disclaims it; quote the line |
| `out-of-scope-undeclared` | Genuinely outside the boundary but not yet written down |

## Procedure

1. Restate the capability in one sentence, in attacker terms.
2. Check `THREAT-MODEL.md` for an existing disclaimer. Quote it if present.
3. Check whether a control exists in `network/policy.nft.in`, `config/torrc`,
   or `src/amnesic_pi/`. Cite `file:line`.
4. Emit the verdict plus the citation.

## Known out-of-scope, already declared

Browser and device fingerprinting, application-layer identity leaks, endpoint
compromise, malicious firmware, physical attacks on powered hardware, malicious
Tor exits, global traffic correlation. Do not re-litigate these; quote and move on.

## Refuse

Answering `in-scope-addressed` without a `file:line` citation. That is the whole
point of this skill.

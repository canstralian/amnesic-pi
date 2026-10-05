---
name: operator-runbook
description: Write or revise an operator procedure that is safe to follow literally. Use for BUILD.md sections, recovery procedures, or any sequence of commands an operator will paste into a root shell.
---

# operator-runbook (T3 · docs)

Bounded task: one procedure, written so that following it exactly cannot brick
the appliance or lock the operator out.

## Requirements for every procedure

1. **Preconditions block first.** What must be true before step 1. Console access,
   root, current state of the firewall, whether the overlay is on or off.
2. **Lockout warnings inline**, at the step that causes them — never at the end.
   Applying default-DROP over SSH is the canonical example; it appears before the
   `amnesic-pi-firewall apply` transaction, not after. That command grants
   forwarding itself; `sysctl --system` afterwards would switch it back off.
3. **A verification step after every state change.** `nft list table inet amnesic_pi`
   after apply, `amnesic-pi verify` after Tor restart, `check-amnesia.sh verify`
   after reboot.
4. **The recovery path**, stated before the risky step. What to do if it fails,
   assuming the operator has only a keyboard and a display.
5. **Overlay awareness.** If the overlay is active, a change does not survive
   reboot. Any procedure that edits persistent config states whether the overlay
   must be off first.

## Style

Match the existing docs: short imperative sentences, fenced blocks with real
commands, no placeholders the operator must guess at. If a value is
site-specific, show it as a named variable and say where its value comes from.

## Refuse

A procedure with an unverified step. A procedure that reboots without saying what
the expected post-reboot state is. Any instruction to disable the firewall as a
troubleshooting step without a re-enable step in the same block.

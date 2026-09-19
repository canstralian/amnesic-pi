---
name: unsafe-interpolation-scan
description: Audit subprocess and shell call sites for unquoted or unvalidated interpolation. Use before signing RUNTIME_SOUND, or whenever src/amnesic_pi or the shell scripts are edited.
---

# unsafe-interpolation-scan (T3 · runtime)

Bounded task: find every place operator-controlled input reaches a command.

## Procedure

1. Enumerate call sites: `subprocess.`, `os.system`, backticks, `eval`, `$(...)`,
   and any `"$VAR"` that is unquoted in `bin/`, `scripts/`, `image/`, `tests/integration/`.
2. For each, trace the input back to its source. Stop only at a literal or a
   validated value.
3. Classify:
   - **safe** — literal, or list-form `subprocess.run([...])` with validated args
   - **validated** — passes through `Config.validate()` or an equivalent regex gate
   - **finding** — reaches a command without a validator between it and the shell

## What "validated" means here

`_IFACE_RE` in `src/amnesic_pi/config.py` is the gate for interface names, and
`TOR_USER` has its own pattern. `tests/test_config.py::test_reject_shell_metacharacters_in_interface`
is the regression test. If you propose relaxing either pattern, that is a policy
change and routes to T1 — refuse it here.

## Hard rules

- `shell=True` is a finding, always.
- String-concatenated commands are a finding, always.
- In shell scripts, every variable expansion is double-quoted. `set -euo pipefail`
  is present. Missing either is a finding.

## Output

`file:line — call site — classification — input provenance`. Findings first.

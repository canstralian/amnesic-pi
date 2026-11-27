# AP-RM-001 — offline content admission (proposed)

Reviewed upstream base: `9e1fb91b6eaaba6da44530c8d63a879e11b9824b`.
This optional slice is not enabled at boot. It adds no service, dependency,
firewall exception, persistence mount, radio, AI, or downstream connectivity.

## Contract

An operator supplies a previously curated, preferably read-only content directory
and an independently trusted SHA-256 digest of its exact `manifest.json` bytes.
The pin must come from a trusted release or separate authenticated channel; a
hash calculated from an untrusted bundle is not an authenticity check.

The manifest is UTF-8 JSON with exactly the fields below. Each filename must be a
single ASCII component (no paths), distinct from `manifest.json`. The manifest is
limited to 1 MiB and 1–1024 entries. File sizes are exact nonnegative integers.
SHA-256 values are lowercase hex. Example shape (replace the digest with the
actual file hash and size with the actual byte count):

```json
{"version":1,"files":[{"name":"guide.txt","bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]}
```

The example digest is for the three bytes `abc`, not real emergency advice.

On Linux, run as an unprivileged operator from the project checkout:

```sh
PYTHONPATH=src python -m amnesic_pi.resilience /path/to/curated-content \
  --manifest-sha256 "$TRUSTED_MANIFEST_SHA256"
```

Exit 0 means all listed bytes matched; exit 1 means verification failed. Exit 2
means invalid CLI arguments (including empty or whitespace-only root paths). Extra
files are not verified and must never be served based on this result. There is
no automatic activation, publishing, copying, mounting or repair. No root access
is needed for ordinary readable files. Do not point this at an untrusted device
filesystem; use an operator-controlled, immutable/read-only directory with trusted
ancestors and no special device files. Symlinks at the root and file level are
rejected. The verifier streams files with bounded per-read memory; large trusted
files still require time and energy to read.

## Threat boundary

This verifies integrity at read time, not provenance of an untrusted pin,
freshness, correctness of advice, protection against a malicious root, or
continued integrity after verification. It is not a security sandbox or an
atomic multi-file snapshot. A later serving layer must consume the same immutable
verified content and expose only manifest entries, enforce freshness policy and
isolate private documents from any shared portal. No persistent logs are written.

## Gates and staged rollout

1. Apply the additive patch locally after confirming the base and pending PRs.
   Run focused tests, the repository's full test suite and Ruff checks; review diff.
2. Resolve the existing authority-hardening PR #9 and verify its current status.
   Current reviewed firewall redirects all downstream TCP to Tor; do not add a
   generic LAN bypass to make an HTTP portal work.
3. Specify an opt-in downstream-only knowledge service with explicit destination,
   interface and port constraints; test no upstream listener, no forwarding,
   no clearnet fallback, no DNS/IPv6 leak and no access to private data. This is
   a separate approval and threat-model change, not part of AP-RM-001.
4. Test the target Pi's boot ordering, Tor-stop denial and reboot amnesia before
   claiming fail-closed operation. Add power telemetry and endurance testing only
   after a measured baseline. The emergency kit must not depend solely on the Pi.

No release, network policy modification or hardware activation is authorised by
this document.

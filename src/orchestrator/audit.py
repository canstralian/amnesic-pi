"""Append-only, hash-chained audit log with an independent mirror.

Invariant I4: every dispatch, status update, gate result, and escalation is
appended to a hash-chained JSONL log, mirrored to a second sink. A break in the
chain is a SEV-2 and halts dispatch. Divergence between sinks is a SEV-1.

Invariant I6: orchestrator state is a projection of this log. Nothing is
authoritative because it is held in memory.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from .errors import AuditChainError, AuditDivergenceError
from .schema import canonical_json, sha256_hex, utcnow

GENESIS_HASH = "0" * 64

_CORE_FIELDS = ("ts", "seq", "actor", "event", "prev_hash")


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: datetime
    actor: str
    event: str
    prev_hash: str
    fields: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ts": self.ts.isoformat(),
            "seq": self.seq,
            "actor": self.actor,
            "event": self.event,
            "prev_hash": self.prev_hash,
        }
        out.update(self.fields)
        return out

    def entry_hash(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))


def _entry_from_dict(raw: dict[str, Any]) -> AuditEntry:
    missing = [name for name in _CORE_FIELDS if name not in raw]
    if missing:
        raise AuditChainError(f"audit entry is missing core fields: {', '.join(missing)}")
    fields = {k: v for k, v in raw.items() if k not in _CORE_FIELDS}
    try:
        ts = datetime.fromisoformat(raw["ts"])
    except (TypeError, ValueError) as exc:
        # A corrupt timestamp is tampering with the log, so it has to surface as
        # an audit incident. Letting ValueError escape turned the documented
        # SEV-2 READ_ONLY readout into a traceback.
        raise AuditChainError(
            f"audit entry at seq {raw.get('seq')!r} has an unparseable timestamp "
            f"{raw['ts']!r}. SEV-2: halt dispatch and replay from the mirror."
        ) from exc
    return AuditEntry(
        seq=raw["seq"],
        ts=ts,
        actor=raw["actor"],
        event=raw["event"],
        prev_hash=raw["prev_hash"],
        fields=fields,
    )


class AuditLog:
    """Write-ahead, fsync-ed, hash-chained JSONL.

    The mirror is written to a separate path so it can be pointed at a different
    failure domain. Both sinks receive the identical canonical line, so any
    divergence is a real integrity event rather than a formatting artefact.

    Known property: a hash chain binds every entry except the tail, because no
    later entry commits to the tail's hash yet. Tampering with the most recent
    entry is therefore caught by ``check_mirror``, not by ``verify_chain``. Run
    both on cold start; running only the chain check leaves a one-entry window.
    """

    def __init__(self, primary: Path, mirror: Path | None = None, *, clock: Any = utcnow) -> None:
        self._primary = Path(primary)
        self._mirror = Path(mirror) if mirror is not None else None
        self._clock = clock
        self._primary.parent.mkdir(parents=True, exist_ok=True)
        if self._mirror is not None:
            self._mirror.parent.mkdir(parents=True, exist_ok=True)
        self._cached_head: AuditEntry | None = None
        self._cached_size = -1

    def _primary_size(self) -> int:
        return self._primary.stat().st_size if self._primary.exists() else 0

    @property
    def path(self) -> Path:
        return self._primary

    @property
    def mirror_path(self) -> Path | None:
        return self._mirror

    def _read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def entries(self) -> Iterator[AuditEntry]:
        for lineno, line in enumerate(self._read_lines(self._primary), start=1):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditChainError(f"{self._primary}:{lineno}: not valid JSON: {exc}") from exc
            yield _entry_from_dict(raw)

    def head(self) -> AuditEntry | None:
        """The last entry, re-scanned only when the file changed underneath us.

        Scanning the whole log on every append made append quadratic in the
        number of entries. The size check is what makes the cache safe: any
        write by another process changes it and forces a re-read.
        """
        size = self._primary_size()
        if size == self._cached_size:
            return self._cached_head
        last: AuditEntry | None = None
        for entry in self.entries():
            last = entry
        self._cached_head = last
        self._cached_size = size
        return last

    def next_seq(self) -> int:
        head = self.head()
        return 0 if head is None else head.seq + 1

    def _write(self, path: Path, line: str) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append(self, actor: str, event: str, **fields: Any) -> AuditEntry:
        """Append one entry, chaining it to the current head. Never overwrites."""
        for name in _CORE_FIELDS:
            if name in fields:
                raise AuditChainError(f"cannot override core audit field {name!r}")
        # Computing seq/prev_hash and writing must be one critical section.
        # Unlocked, two concurrent appends read the same head and emit the same
        # seq with the same prev_hash — a chain break on an append-only log,
        # which is exactly the corruption this log exists to detect.
        with self._primary.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                head = self.head()
                entry = AuditEntry(
                    seq=0 if head is None else head.seq + 1,
                    ts=self._clock(),
                    actor=actor,
                    event=event,
                    prev_hash=GENESIS_HASH if head is None else head.entry_hash(),
                    fields=fields,
                )
                line = canonical_json(entry.to_dict())
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
                self._cached_head = entry
                self._cached_size = self._primary_size()
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        if self._mirror is not None:
            self._write(self._mirror, line)
        return entry

    def verify_chain(self) -> int:
        """Replay the chain. Returns the entry count, raises on any break."""
        expected_prev = GENESIS_HASH
        expected_seq = 0
        count = 0
        for entry in self.entries():
            if entry.seq != expected_seq:
                raise AuditChainError(
                    f"audit sequence gap: expected seq {expected_seq}, found {entry.seq}. "
                    "SEV-2: halt dispatch and replay from the mirror."
                )
            if entry.prev_hash != expected_prev:
                raise AuditChainError(
                    f"audit chain break at seq {entry.seq}: prev_hash {entry.prev_hash} "
                    f"does not match the preceding entry hash {expected_prev}. "
                    "SEV-2: halt dispatch and replay from the mirror."
                )
            expected_prev = entry.entry_hash()
            expected_seq += 1
            count += 1
        return count

    def check_mirror(self) -> None:
        """Compare sinks byte-for-byte. Divergence is a SEV-1."""
        if self._mirror is None:
            return
        primary = self._read_lines(self._primary)
        mirror = self._read_lines(self._mirror)
        if len(mirror) < len(primary):
            raise AuditDivergenceError(
                f"audit mirror is behind by {len(primary) - len(mirror)} entries "
                "(SEV-1 if it does not converge)"
            )
        if len(mirror) > len(primary):
            raise AuditDivergenceError(
                f"audit mirror has {len(mirror) - len(primary)} entries the primary does not. "
                "SEV-1: unauthorized write to a sink."
            )
        for index, (left, right) in enumerate(zip(primary, mirror)):
            if left != right:
                raise AuditDivergenceError(
                    f"audit sinks diverge at entry {index}. SEV-1: forensic replay required."
                )

"""Handoff tokens: HMAC-SHA256 signing, hourly rotation, replay rejection.

Invariant I2 requires every task to be signed before dispatch, and team lead
ingress to drop anything unsigned. Invariant I5 requires the token to carry the
maximum authority tier so the dispatcher can reject overreach rather than
trusting the caller.

    token = HMAC_SHA256(key, f"{task_id}|{team}|{tier_max}|{scope_digest}|{expiry}")

The scope digest is the SHA-256 of the canonical payload, so any tamper between
signing and ingress invalidates the signature.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .errors import ReplayError, TokenError
from .schema import DISPATCHABLE_TIERS, payload_digest, utcnow

DEFAULT_ROTATION = timedelta(hours=1)
DEFAULT_TTL = timedelta(minutes=30)

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_task_id(now_ms: int | None = None) -> str:
    """A ULID: 48 bits of millisecond time, then 80 bits of randomness."""
    millis = int(time.time() * 1000) if now_ms is None else now_ms
    value = (millis << 80) | secrets.randbits(80)
    chars = []
    for shift in range(125, -1, -5):
        chars.append(_CROCKFORD[(value >> shift) & 0x1F])
    return "".join(chars)


@dataclass(frozen=True)
class HandoffToken:
    """A signed grant of bounded authority over exactly one task."""

    task_id: str
    team: str
    tier_max: str
    scope_digest: str
    expiry: datetime
    key_id: str
    mac: str

    def message(self) -> str:
        return (
            f"{self.task_id}|{self.team}|{self.tier_max}|"
            f"{self.scope_digest}|{self.expiry.isoformat()}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "team": self.team,
            "tier_max": self.tier_max,
            "scope_digest": self.scope_digest,
            "expiry": self.expiry.isoformat(),
            "key_id": self.key_id,
            "mac": self.mac,
        }


@dataclass(frozen=True)
class _Key:
    key_id: str
    material: bytes
    created_at: datetime


class KeyRing:
    """Rotating HMAC key material.

    Two keys are live at any moment: the current signing key and the previous
    one, which stays verifiable so tasks signed just before a rotation are not
    dropped in flight. Anything older is gone, which bounds the window in which
    a leaked key is useful.
    """

    def __init__(
        self,
        rotation: timedelta = DEFAULT_ROTATION,
        *,
        clock: Any = utcnow,
        seed: bytes | None = None,
    ) -> None:
        if rotation <= timedelta(0):
            raise TokenError("key rotation interval must be positive")
        self._rotation = rotation
        self._clock = clock
        self._keys: list[_Key] = []
        self._rotate(seed)

    def _rotate(self, seed: bytes | None = None) -> _Key:
        material = seed if seed is not None else os.urandom(32)
        key = _Key(key_id=secrets.token_hex(8), material=material, created_at=self._clock())
        self._keys.insert(0, key)
        del self._keys[2:]
        return key

    def current(self) -> _Key:
        now = self._clock()
        if now - self._keys[0].created_at >= self._rotation:
            return self._rotate()
        return self._keys[0]

    def rotate_now(self) -> None:
        """Force a rotation. Used by the operator CLI and by key revocation."""
        self._rotate()

    def _lookup(self, key_id: str) -> _Key:
        for key in self._keys:
            if hmac.compare_digest(key.key_id, key_id):
                return key
        raise TokenError(f"token signed with unknown or retired key: {key_id}")

    def sign(
        self,
        *,
        task_id: str,
        team: str,
        tier_max: str,
        payload: Any,
        ttl: timedelta = DEFAULT_TTL,
    ) -> HandoffToken:
        if tier_max not in DISPATCHABLE_TIERS:
            raise TokenError(
                f"refusing to sign tier_max={tier_max!r}; the orchestrator never grants "
                f"authority outside {DISPATCHABLE_TIERS} (invariant I5)"
            )
        if ttl <= timedelta(0):
            raise TokenError("token TTL must be positive")
        key = self.current()
        scope_digest = payload_digest(payload)
        expiry = self._clock() + ttl
        unsigned = HandoffToken(
            task_id=task_id,
            team=team,
            tier_max=tier_max,
            scope_digest=scope_digest,
            expiry=expiry,
            key_id=key.key_id,
            mac="",
        )
        mac = hmac.new(key.material, unsigned.message().encode("utf-8"), "sha256").hexdigest()
        return HandoffToken(
            task_id=task_id,
            team=team,
            tier_max=tier_max,
            scope_digest=scope_digest,
            expiry=expiry,
            key_id=key.key_id,
            mac=mac,
        )

    def verify(
        self,
        token: HandoffToken,
        *,
        payload: Any,
        team: str | None = None,
        required_tier: str | None = None,
    ) -> None:
        """Verify a token at team lead ingress. Raises on any failure.

        Checks, in order: key is live, signature matches, token has not expired,
        payload has not been tampered with, and the delivered team matches the
        signed one. A caller asking for authority above ``tier_max`` is rejected
        here rather than at the tool boundary.
        """
        key = self._lookup(token.key_id)
        expected = hmac.new(key.material, token.message().encode("utf-8"), "sha256").hexdigest()
        if not hmac.compare_digest(expected, token.mac):
            raise TokenError(f"handoff token signature mismatch for task {token.task_id}")
        if self._clock() >= token.expiry:
            raise TokenError(f"handoff token for task {token.task_id} expired at {token.expiry}")
        if not hmac.compare_digest(payload_digest(payload), token.scope_digest):
            raise TokenError(
                f"payload for task {token.task_id} does not match the signed scope digest; "
                "the task was modified after signing"
            )
        if team is not None and not hmac.compare_digest(team, token.team):
            raise TokenError(
                f"task {token.task_id} was signed for team {token.team!r} "
                f"but delivered to {team!r}"
            )
        if required_tier is not None:
            if required_tier not in DISPATCHABLE_TIERS:
                raise TokenError(
                    f"task {token.task_id} requests {required_tier!r} authority; a handoff "
                    f"token only ever grants {DISPATCHABLE_TIERS}. T1 is out of reach by "
                    "construction, and T4 is reached through a T2-approved action manifest."
                )
            # TIERS is ordered most-authoritative first, so a *lower* index means
            # more authority. A grant covers its own tier and everything below it.
            permitted = DISPATCHABLE_TIERS.index(token.tier_max)
            requested = DISPATCHABLE_TIERS.index(required_tier)
            if requested < permitted:
                raise TokenError(
                    f"task {token.task_id} requests {required_tier} authority but its token "
                    f"grants at most {token.tier_max} (invariant I5)"
                )


class ReplayLedger:
    """Single-use enforcement for state-changing operations.

    Tokens are consumed by ``(task_id, mac)``. Presenting the same pair twice is
    a replay and is refused. Resubmitting an *unconsumed* token is a no-op at
    the dispatcher instead, which is what keeps dispatch idempotent on task_id.
    """

    def __init__(self) -> None:
        self._consumed: dict[str, str] = {}

    def consume(self, token: HandoffToken) -> None:
        prior = self._consumed.get(token.task_id)
        if prior is not None:
            raise ReplayError(
                f"handoff token for task {token.task_id} was already consumed; "
                "replay refused (invariant I2)"
            )
        self._consumed[token.task_id] = token.mac

    def was_consumed(self, task_id: str) -> bool:
        return task_id in self._consumed

    def prune(self, before: datetime) -> None:
        """Consumed entries older than the key window cannot be replayed anyway."""
        del before  # retention is bounded by key rotation, not by this ledger

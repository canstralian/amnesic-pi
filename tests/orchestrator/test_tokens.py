"""Invariant I2: every task is signed, and nothing unsigned or stale is accepted.

Invariant I5: the token carries the authority ceiling, so overreach is rejected
at the dispatcher rather than trusted at the tool boundary.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from orchestrator.errors import ReplayError, TokenError
from orchestrator.tokens import KeyRing, ReplayLedger, new_task_id

PAYLOAD = {"node_id": "deny-quic", "acceptance": ["nft -c accepts"]}


class FrozenClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def test_task_ids_are_unique_sortable_ulids():
    ids = {new_task_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(len(value) == 26 for value in ids)
    earlier = new_task_id(now_ms=1_000_000)
    later = new_task_id(now_ms=2_000_000)
    assert earlier < later


def test_round_trip_verifies(keyring: KeyRing):
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    keyring.verify(token, payload=PAYLOAD, team="policy", required_tier="T2")


def test_payload_tamper_invalidates_the_token(keyring: KeyRing):
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    with pytest.raises(TokenError, match="signed scope digest"):
        keyring.verify(token, payload={**PAYLOAD, "acceptance": ["anything goes"]})


def test_signature_tamper_is_detected(keyring: KeyRing):
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    forged = type(token)(**{**token.to_dict(), "expiry": token.expiry, "mac": "0" * 64})
    with pytest.raises(TokenError, match="signature mismatch"):
        keyring.verify(forged, payload=PAYLOAD)


def test_team_substitution_is_detected(keyring: KeyRing):
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    with pytest.raises(TokenError, match="delivered to"):
        keyring.verify(token, payload=PAYLOAD, team="release")


def test_tier_overreach_is_rejected(keyring: KeyRing):
    """A T3 grant cannot be used to request T2 authority (invariant I5)."""
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T3", payload=PAYLOAD)
    with pytest.raises(TokenError, match="grants at most T3"):
        keyring.verify(token, payload=PAYLOAD, required_tier="T2")


def test_orchestrator_never_signs_above_t2(keyring: KeyRing):
    for tier in ("T1", "T4", "root"):
        with pytest.raises(TokenError, match="invariant I5"):
            keyring.sign(task_id=new_task_id(), team="policy", tier_max=tier, payload=PAYLOAD)


def test_expired_tokens_are_dropped():
    clock = FrozenClock(datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc))
    ring = KeyRing(rotation=timedelta(hours=1), clock=clock, seed=b"\x02" * 32)
    token = ring.sign(
        task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD, ttl=timedelta(minutes=5)
    )
    ring.verify(token, payload=PAYLOAD)
    clock.advance(timedelta(minutes=6))
    with pytest.raises(TokenError, match="expired"):
        ring.verify(token, payload=PAYLOAD)


def test_previous_key_stays_verifiable_across_one_rotation():
    """A task signed just before a rotation must not be dropped in flight."""
    clock = FrozenClock(datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc))
    ring = KeyRing(rotation=timedelta(hours=1), clock=clock, seed=b"\x03" * 32)
    token = ring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    ring.rotate_now()
    ring.verify(token, payload=PAYLOAD)


def test_key_retired_after_two_rotations_drops_the_token():
    clock = FrozenClock(datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc))
    ring = KeyRing(rotation=timedelta(hours=1), clock=clock, seed=b"\x04" * 32)
    token = ring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    ring.rotate_now()
    ring.rotate_now()
    with pytest.raises(TokenError, match="unknown or retired key"):
        ring.verify(token, payload=PAYLOAD)


def test_single_use_enforcement(keyring: KeyRing):
    token = keyring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=PAYLOAD)
    ledger = ReplayLedger()
    ledger.consume(token)
    assert ledger.was_consumed(token.task_id)
    with pytest.raises(ReplayError, match="already consumed"):
        ledger.consume(token)

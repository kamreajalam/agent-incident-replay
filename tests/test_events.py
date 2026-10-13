"""Unit tests for IncidentEvent, canonical serialization, and SHA-256 chaining."""

import json
import pytest

from agent_incident_replay.events import (
    GENESIS_PREV_HASH,
    IncidentEvent,
    InvalidEventError,
    canonical_json,
    compute_sha256,
    format_utc_timestamp,
    validate_utc_timestamp,
)


def test_canonical_json_sorts_keys() -> None:
    data1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    data2 = {"a": 2, "z": 1, "m": {"a": 4, "b": 3}}
    assert canonical_json(data1) == canonical_json(data2)
    assert canonical_json(data1) == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_format_and_validate_utc_timestamp() -> None:
    ts = format_utc_timestamp()
    assert ts.endswith("Z")
    assert validate_utc_timestamp(ts) is True
    assert validate_utc_timestamp("2026-10-14T02:15:00Z") is True
    assert validate_utc_timestamp("2026-10-14T02:15:00.123456Z") is True
    assert validate_utc_timestamp("2026-10-14 02:15:00") is False
    assert validate_utc_timestamp("2026-10-14T02:15:00+05:30") is False
    assert validate_utc_timestamp("not-a-timestamp") is False


def test_compute_sha256() -> None:
    digest1 = compute_sha256("test-content")
    digest2 = compute_sha256("test-content")
    digest3 = compute_sha256("different-content")
    assert len(digest1) == 64
    assert digest1 == digest2
    assert digest1 != digest3


def test_create_incident_event() -> None:
    event = IncidentEvent.create(
        session_id="session_01",
        sequence=1,
        event_type="ACTION_PROPOSED",
        payload={"action": "test", "val": 42},
        prev_hash=GENESIS_PREV_HASH,
        timestamp="2026-10-14T00:00:00Z",
    )
    assert event.session_id == "session_01"
    assert event.sequence == 1
    assert event.event_type == "ACTION_PROPOSED"
    assert event.payload == {"action": "test", "val": 42}
    assert event.prev_hash == GENESIS_PREV_HASH
    assert len(event.hash) == 64
    assert event.verify_hash() is True


def test_event_to_and_from_dict() -> None:
    event = IncidentEvent.create(
        session_id="session_01",
        sequence=1,
        event_type="POLICY_DECISION",
        payload={"decision": "ALLOW"},
        timestamp="2026-10-14T00:00:00Z",
    )
    d = event.to_dict()
    restored = IncidentEvent.from_dict(d)
    assert restored == event
    assert restored.verify_hash() is True


def test_event_to_and_from_json() -> None:
    event = IncidentEvent.create(
        session_id="session_01",
        sequence=1,
        event_type="EXECUTION_RESULT",
        payload={"status": "SUCCESS"},
        timestamp="2026-10-14T00:00:00Z",
    )
    json_str = event.to_json()
    restored = IncidentEvent.from_json(json_str)
    assert restored == event
    assert restored.verify_hash() is True


def test_tampered_payload_fails_verification() -> None:
    event = IncidentEvent.create(
        session_id="session_01",
        sequence=1,
        event_type="ACTION_PROPOSED",
        payload={"amount": 500},
        timestamp="2026-10-14T00:00:00Z",
    )
    assert event.verify_hash() is True

    # Create modified clone with altered payload but original hash
    tampered_dict = event.to_dict()
    tampered_dict["payload"] = {"amount": 5000}
    tampered_event = IncidentEvent.from_dict(tampered_dict)
    assert tampered_event.verify_hash() is False


def test_invalid_event_attributes_raise() -> None:
    with pytest.raises(InvalidEventError):
        IncidentEvent(
            session_id="",
            sequence=1,
            timestamp="2026-10-14T00:00:00Z",
            event_type="TEST",
            payload={},
            prev_hash=GENESIS_PREV_HASH,
        )

    with pytest.raises(InvalidEventError):
        IncidentEvent(
            session_id="s1",
            sequence=0,  # Invalid sequence < 1
            timestamp="2026-10-14T00:00:00Z",
            event_type="TEST",
            payload={},
            prev_hash=GENESIS_PREV_HASH,
        )

    with pytest.raises(InvalidEventError):
        IncidentEvent(
            session_id="s1",
            sequence=1,
            timestamp="invalid-timestamp",
            event_type="TEST",
            payload={},
            prev_hash=GENESIS_PREV_HASH,
        )

    with pytest.raises(InvalidEventError):
        IncidentEvent(
            session_id="s1",
            sequence=1,
            timestamp="2026-10-14T00:00:00Z",
            event_type="TEST",
            payload={},
            prev_hash="short_hash",
        )

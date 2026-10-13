"""Unit tests for IncidentVerifier and tamper detection."""

import json
from pathlib import Path
import pytest

from agent_incident_replay.recorder import SessionRecorder, get_session_path
from agent_incident_replay.verifier import IncidentVerifier


@pytest.fixture
def sample_session(tmp_path: Path) -> tuple[str, Path]:
    session_id = "verifier_session"
    recorder = SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    recorder.record_action_proposed(action="refund", parameters={"amount": 5000})
    recorder.record_policy_decision(decision="BLOCK", reason="Limit exceeded")
    recorder.record_execution_result(status="NOT_EXECUTED", external_effect="NOT_INDEPENDENTLY_VERIFIED")
    recorder.record_incident_closed(resolution="CLOSED_BLOCKED")
    session_file = get_session_path(session_id, tmp_path)
    return session_id, session_file


def test_verify_valid_session(sample_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_file = sample_session
    verifier = IncidentVerifier()
    res = verifier.verify_session(session_id, storage_dir=tmp_path)
    assert res.is_valid is True
    assert res.event_count == 4
    assert res.failed_sequence is None
    assert res.error_message is None
    assert res.head_hash is not None
    assert res.root_hash is not None


def test_verify_nonexistent_file(tmp_path: Path) -> None:
    verifier = IncidentVerifier()
    res = verifier.verify_file(tmp_path / "does_not_exist.jsonl")
    assert res.is_valid is False
    assert "not found" in res.error_message.lower()


def test_verify_empty_file(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_text("", encoding="utf-8")
    verifier = IncidentVerifier()
    res = verifier.verify_file(empty_file)
    assert res.is_valid is False
    assert "empty" in res.error_message.lower()


def test_verify_corrupted_json(tmp_path: Path) -> None:
    corrupt_file = tmp_path / "corrupt.jsonl"
    corrupt_file.write_text("{\"sequence\": 1, invalid json\n", encoding="utf-8")
    verifier = IncidentVerifier()
    res = verifier.verify_file(corrupt_file)
    assert res.is_valid is False
    assert "corrupt json" in res.error_message.lower()


def test_tamper_payload_detection(sample_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_file = sample_session
    lines = session_file.read_text(encoding="utf-8").splitlines()

    # Tamper with event 2 (POLICY_DECISION): change "BLOCK" to "ALLOW"
    ev2 = json.loads(lines[1])
    assert ev2["event_type"] == "POLICY_DECISION"
    ev2["payload"]["decision"] = "ALLOW"
    lines[1] = json.dumps(ev2)

    tampered_file = tmp_path / "tampered_payload.jsonl"
    tampered_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = IncidentVerifier()
    res = verifier.verify_file(tampered_file, expected_session_id=session_id)
    assert res.is_valid is False
    assert res.failed_sequence == 2
    assert res.failed_event_type == "POLICY_DECISION"
    assert "hash mismatch" in res.error_message.lower()


def test_tamper_reorder_detection(sample_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_file = sample_session
    lines = session_file.read_text(encoding="utf-8").splitlines()

    # Swap event 1 and event 2
    lines[0], lines[1] = lines[1], lines[0]
    tampered_file = tmp_path / "swapped_events.jsonl"
    tampered_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = IncidentVerifier()
    res = verifier.verify_file(tampered_file, expected_session_id=session_id)
    assert res.is_valid is False
    # Will fail sequence discontinuity or prev_hash
    assert res.failed_sequence in (1, 2)


def test_tamper_prev_hash_broken(sample_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_file = sample_session
    lines = session_file.read_text(encoding="utf-8").splitlines()

    # Modify prev_hash on event 3
    ev3 = json.loads(lines[2])
    ev3["prev_hash"] = "1" * 64
    lines[2] = json.dumps(ev3)

    tampered_file = tmp_path / "broken_chain.jsonl"
    tampered_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = IncidentVerifier()
    res = verifier.verify_file(tampered_file, expected_session_id=session_id)
    assert res.is_valid is False
    assert res.failed_sequence == 3
    assert res.failed_event_type == "EXECUTION_RESULT"
    assert "broken hash chain" in res.error_message.lower()


def test_tamper_session_id_mismatch(sample_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_file = sample_session
    lines = session_file.read_text(encoding="utf-8").splitlines()

    ev2 = json.loads(lines[1])
    ev2["session_id"] = "different_session"
    lines[1] = json.dumps(ev2)

    tampered_file = tmp_path / "mismatched_session.jsonl"
    tampered_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = IncidentVerifier()
    res = verifier.verify_file(tampered_file, expected_session_id=session_id)
    assert res.is_valid is False
    assert res.failed_sequence == 2
    assert "session id mismatch" in res.error_message.lower()

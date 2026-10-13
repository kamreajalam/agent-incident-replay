"""Unit tests for SessionRecorder and storage resolution."""

import os
from pathlib import Path
import pytest

from agent_incident_replay.events import GENESIS_PREV_HASH
from agent_incident_replay.recorder import (
    SessionAlreadyExistsError,
    SessionRecorder,
    get_reports_dir,
    get_session_path,
    get_sessions_dir,
    get_storage_dir,
)


def test_storage_dir_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Direct override
    override = tmp_path / "custom_override"
    assert get_storage_dir(override) == override.resolve()

    # 2. Env variable
    env_dir = tmp_path / "env_home"
    monkeypatch.setenv("AGENT_INCIDENT_REPLAY_HOME", str(env_dir))
    assert get_storage_dir() == env_dir.resolve()
    assert get_sessions_dir() == env_dir.resolve() / "sessions"
    assert get_reports_dir() == env_dir.resolve() / "reports"
    assert get_session_path("run_test") == env_dir.resolve() / "sessions" / "run_test.jsonl"


def test_record_events_creates_file_and_chains_hashes(tmp_path: Path) -> None:
    session_id = "test_run_01"
    recorder = SessionRecorder(session_id=session_id, storage_dir=tmp_path)

    assert recorder.event_count == 0
    assert recorder.current_hash == GENESIS_PREV_HASH

    e1 = recorder.record_action_proposed(action="refund", parameters={"amount": 500})
    assert e1.sequence == 1
    assert e1.prev_hash == GENESIS_PREV_HASH
    assert recorder.current_hash == e1.hash
    assert recorder.event_count == 1

    e2 = recorder.record_policy_decision(decision="BLOCK", reason="Limit exceeded")
    assert e2.sequence == 2
    assert e2.prev_hash == e1.hash
    assert recorder.current_hash == e2.hash
    assert recorder.event_count == 2

    e3 = recorder.record_execution_result(status="NOT_EXECUTED")
    assert e3.sequence == 3
    assert e3.prev_hash == e2.hash

    e4 = recorder.record_incident_closed(resolution="CLOSED_BLOCKED")
    assert e4.sequence == 4
    assert e4.prev_hash == e3.hash

    # Check file exists and has 4 lines
    session_file = get_session_path(session_id, tmp_path)
    assert session_file.exists()
    lines = [line.strip() for line in session_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 4


def test_refuse_silent_overwrite(tmp_path: Path) -> None:
    session_id = "protected_session"
    # Create first recorder
    rec1 = SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    rec1.record("ACTION_PROPOSED", {"action": "initial"})

    # Attempt to initialize another recorder with same session ID without allow_overwrite
    with pytest.raises(SessionAlreadyExistsError) as exc_info:
        SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    assert "Silent overwriting of existing sessions is prohibited" in str(exc_info.value)

    # Initializing with allow_overwrite=True succeeds and clears file
    rec2 = SessionRecorder(session_id=session_id, storage_dir=tmp_path, allow_overwrite=True)
    assert rec2.event_count == 0
    e_new = rec2.record("ACTION_PROPOSED", {"action": "overwritten"})
    assert e_new.sequence == 1

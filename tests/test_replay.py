"""Unit tests for IncidentReplayer (read-only playback)."""

import io
from pathlib import Path
import pytest

from agent_incident_replay.recorder import SessionRecorder, get_session_path
from agent_incident_replay.replay import IncidentReplayer


@pytest.fixture
def replay_session(tmp_path: Path) -> tuple[str, Path]:
    session_id = "replay_session_01"
    recorder = SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    recorder.record_action_proposed(action="process_refund", parameters={"amount": 5000})
    recorder.record_policy_decision(decision="BLOCK", reason="Limit check")
    recorder.record_execution_result(status="NOT_EXECUTED", external_effect="NOT_INDEPENDENTLY_VERIFIED")
    recorder.record_incident_closed(resolution="CLOSED")
    path = get_session_path(session_id, tmp_path)
    return session_id, path


def test_replay_is_strictly_read_only(replay_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_path = replay_session
    initial_content = session_path.read_text(encoding="utf-8")
    initial_mtime = session_path.stat().st_mtime_ns

    replayer = IncidentReplayer()
    out = io.StringIO()
    lines = replayer.replay(session_id, storage_dir=tmp_path, out=out)

    # Verify session file was unchanged
    assert session_path.read_text(encoding="utf-8") == initial_content
    assert session_path.stat().st_mtime_ns == initial_mtime

    output_text = out.getvalue()
    assert "READ-ONLY PLAYBACK" in output_text
    assert "process_refund" in output_text
    assert "BLOCK" in output_text
    assert "NOT_EXECUTED" in output_text
    assert "END OF REPLAY" in output_text
    assert len(lines) > 10


def test_replay_nonexistent_session(tmp_path: Path) -> None:
    replayer = IncidentReplayer()
    lines = replayer.replay("nonexistent", storage_dir=tmp_path)
    assert any("INTEGRITY ALERT" in line for line in lines)

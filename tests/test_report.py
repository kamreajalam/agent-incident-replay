"""Unit tests for IncidentReporter (Forensic Markdown Report)."""

import hashlib
from pathlib import Path
import pytest

from agent_incident_replay.recorder import SessionRecorder, get_session_path
from agent_incident_replay.report import IncidentReporter


@pytest.fixture
def report_session(tmp_path: Path) -> tuple[str, Path]:
    session_id = "report_session_01"
    recorder = SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    recorder.record_action_proposed(
        action="transfer_funds",
        parameters={"amount": 5000, "currency": "INR"},
        proposed_by="refund_bot",
    )
    recorder.record_policy_decision(
        decision="BLOCK",
        rule_id="RULE_REFUND_LIMIT",
        reason="Exceeds automatic approval limit of ₹500",
        threshold=500,
    )
    recorder.record_execution_result(
        status="NOT_EXECUTED",
        external_effect="NOT_INDEPENDENTLY_VERIFIED",
        details="Suppressed by policy engine",
    )
    recorder.record_incident_closed(
        resolution="BLOCKED_AND_REFERRED",
        external_effect_status="NOT_INDEPENDENTLY_VERIFIED",
    )
    session_path = get_session_path(session_id, tmp_path)
    return session_id, session_path


def test_generate_report_sections_and_preserves_log(report_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_path = report_session

    # Compute hash and capture mtime of original event log before report generation
    original_log_bytes = session_path.read_bytes()
    original_log_hash = hashlib.sha256(original_log_bytes).hexdigest()
    original_mtime = session_path.stat().st_mtime_ns

    reporter = IncidentReporter()
    report_path = reporter.generate_report(session_id, storage_dir=tmp_path)

    # 1. Report file must exist
    assert report_path.exists()
    assert report_path.name == f"{session_id}.md"

    # 2. Check original event log was NOT modified at all
    assert session_path.read_bytes() == original_log_bytes
    assert hashlib.sha256(session_path.read_bytes()).hexdigest() == original_log_hash
    assert session_path.stat().st_mtime_ns == original_mtime

    # 3. Check report contents for all required sections
    content = report_path.read_text(encoding="utf-8")

    # Session identifier
    assert session_id in content
    # Verification result
    assert "Integrity Verification" in content
    assert "PASSED" in content
    # Incident timeline
    assert "Incident Timeline" in content
    assert "ACTION_PROPOSED" in content
    assert "POLICY_DECISION" in content
    # Policy decision
    assert "BLOCK" in content
    # Execution result
    assert "NOT_EXECUTED" in content
    # External-effect evidence status
    assert "NOT_INDEPENDENTLY_VERIFIED" in content
    # Missing evidence
    assert "Missing Evidence" in content
    assert "Payment Gateway" in content or "Gateway" in content
    # Limitations
    assert "Limitations" in content
    assert "tamper-evident" in content.lower()

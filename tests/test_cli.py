"""Unit tests for the CLI interface and exit codes."""

import json
from pathlib import Path
import pytest

from agent_incident_replay.cli import main
from agent_incident_replay.recorder import SessionRecorder, get_session_path


@pytest.fixture
def cli_session(tmp_path: Path) -> tuple[str, Path]:
    session_id = "cli_test_session"
    recorder = SessionRecorder(session_id=session_id, storage_dir=tmp_path)
    recorder.record_action_proposed(action="refund", parameters={"amount": 5000})
    recorder.record_policy_decision(decision="BLOCK", reason="Limit check")
    recorder.record_execution_result(status="NOT_EXECUTED", external_effect="NOT_INDEPENDENTLY_VERIFIED")
    recorder.record_incident_closed(resolution="CLOSED")
    path = get_session_path(session_id, storage_dir=tmp_path)
    return session_id, path


def test_cli_verify_success(cli_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, _ = cli_session
    code = main(["--home", str(tmp_path), "verify", session_id])
    assert code == 0


def test_cli_verify_tampered_fails(cli_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, session_path = cli_session
    # Tamper with file
    lines = session_path.read_text(encoding="utf-8").splitlines()
    ev1 = json.loads(lines[0])
    ev1["payload"]["amount"] = 999999
    lines[0] = json.dumps(ev1)
    session_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code = main(["--home", str(tmp_path), "verify", session_id])
    assert code == 1


def test_cli_verify_nonexistent(tmp_path: Path) -> None:
    code = main(["--home", str(tmp_path), "verify", "nonexistent_session"])
    assert code == 2


def test_cli_replay_success(cli_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, _ = cli_session
    code = main(["--home", str(tmp_path), "replay", session_id])
    assert code == 0


def test_cli_replay_nonexistent(tmp_path: Path) -> None:
    code = main(["--home", str(tmp_path), "replay", "nonexistent_session"])
    assert code == 2


def test_cli_events_success(cli_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, _ = cli_session
    code = main(["--home", str(tmp_path), "events", session_id])
    assert code == 0


def test_cli_events_json(cli_session: tuple[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    session_id, _ = cli_session
    code = main(["--home", str(tmp_path), "events", session_id, "--json"])
    assert code == 0
    captured = capsys.readouterr()
    lines = [line.strip() for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 4
    for line in lines:
        parsed = json.loads(line)
        assert "hash" in parsed
        assert "sequence" in parsed


def test_cli_events_nonexistent(tmp_path: Path) -> None:
    code = main(["--home", str(tmp_path), "events", "nonexistent_session"])
    assert code == 2


def test_cli_report_success(cli_session: tuple[str, Path], tmp_path: Path) -> None:
    session_id, _ = cli_session
    code = main(["--home", str(tmp_path), "report", session_id])
    assert code == 0
    report_file = tmp_path / "reports" / f"{session_id}.md"
    assert report_file.exists()


def test_cli_report_nonexistent(tmp_path: Path) -> None:
    code = main(["--home", str(tmp_path), "report", "nonexistent_session"])
    assert code == 2


def test_cli_missing_command() -> None:
    # argparse error on missing subcommand returns code 2
    code = main([])
    assert code == 2

"""Command-line interface for Agent Incident Replay.

Provides commands to verify, replay, list events, and generate forensic reports
for incident sessions.

Exit codes:
    0: Success
    1: Verification failure (tamper detected or integrity check failed)
    2: Command, argument, or storage error (session not found, I/O error)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from agent_incident_replay.recorder import get_session_path, get_storage_dir
from agent_incident_replay.replay import IncidentReplayer
from agent_incident_replay.report import IncidentReporter
from agent_incident_replay.verifier import IncidentVerifier, VerificationResult


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="agent-incident-replay",
        description="Tamper-evident forensic logging, integrity verification, and replay for AI agents.",
    )
    parser.add_argument(
        "--home",
        dest="storage_home",
        default=None,
        help="Override base storage directory (defaults to AGENT_INCIDENT_REPLAY_HOME or ~/.agent-incident-replay).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # verify
    verify_p = subparsers.add_parser("verify", help="Cryptographically verify session event chain integrity.")
    verify_p.add_argument("session_id", help="Session identifier or session JSONL file path.")

    # replay
    replay_p = subparsers.add_parser("replay", help="Perform read-only chronological playback of an incident.")
    replay_p.add_argument("session_id", help="Session identifier or session JSONL file path.")

    # events
    events_p = subparsers.add_parser("events", help="List all events recorded in a session.")
    events_p.add_argument("session_id", help="Session identifier or session JSONL file path.")
    events_p.add_argument("--json", action="store_true", help="Print raw canonical JSONL lines.")

    # report
    report_p = subparsers.add_parser("report", help="Generate a forensic Markdown report for a session.")
    report_p.add_argument("session_id", help="Session identifier or session JSONL file path.")

    return parser


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute 'verify' command."""
    storage_dir = args.storage_home
    session_id = args.session_id

    # Check if session_id is a path or an ID
    path = Path(session_id)
    if not path.exists():
        path = get_session_path(session_id, storage_dir)

    if not path.exists():
        sys.stderr.write(f"Error: Session file not found for '{session_id}' (searched: {path})\n")
        return 2

    verifier = IncidentVerifier()
    result: VerificationResult = verifier.verify_file(path, expected_session_id=session_id)

    if result.is_valid:
        sys.stdout.write(f"[PASSED] Session '{result.session_id}' integrity verified.\n")
        sys.stdout.write(f"  Events:    {result.event_count}\n")
        sys.stdout.write(f"  Head Hash: {result.head_hash}\n")
        sys.stdout.write(f"  Root Hash: {result.root_hash}\n")
        return 0
    else:
        sys.stderr.write(f"[FAILED] Integrity verification failed for session '{result.session_id}'.\n")
        if result.failed_sequence is not None:
            sys.stderr.write(f"  Sequence:   {result.failed_sequence}\n")
        if result.failed_event_type is not None:
            sys.stderr.write(f"  Event Type: {result.failed_event_type}\n")
        sys.stderr.write(f"  Reason:     {result.error_message}\n")
        return 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Execute 'replay' command."""
    storage_dir = args.storage_home
    session_id = args.session_id

    path = Path(session_id)
    if not path.exists():
        path = get_session_path(session_id, storage_dir)

    if not path.exists():
        sys.stderr.write(f"Error: Session file not found for '{session_id}' (searched: {path})\n")
        return 2

    replayer = IncidentReplayer()
    replayer.replay(session_id, storage_dir=storage_dir, out=sys.stdout)
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    """Execute 'events' command."""
    storage_dir = args.storage_home
    session_id = args.session_id

    path = Path(session_id)
    if not path.exists():
        path = get_session_path(session_id, storage_dir)

    if not path.exists():
        sys.stderr.write(f"Error: Session file not found for '{session_id}' (searched: {path})\n")
        return 2

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as err:
        sys.stderr.write(f"Error reading session file: {err}\n")
        return 2

    if args.json:
        for line in lines:
            sys.stdout.write(line + "\n")
    else:
        sys.stdout.write(f"Session '{session_id}' contains {len(lines)} event(s):\n")
        for line in lines:
            from agent_incident_replay.events import IncidentEvent
            event = IncidentEvent.from_json(line)
            sys.stdout.write(
                f"  [{event.sequence}] {event.timestamp} | {event.event_type} | hash: {event.hash[:16]}...\n"
            )
            if event.payload:
                for k, v in event.payload.items():
                    sys.stdout.write(f"      {k}: {v}\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Execute 'report' command."""
    storage_dir = args.storage_home
    session_id = args.session_id

    path = Path(session_id)
    if not path.exists():
        path = get_session_path(session_id, storage_dir)

    if not path.exists():
        sys.stderr.write(f"Error: Session file not found for '{session_id}' (searched: {path})\n")
        return 2

    reporter = IncidentReporter()
    try:
        report_path = reporter.generate_report(session_id, storage_dir=storage_dir)
        sys.stdout.write(f"Forensic report generated successfully:\n  {report_path}\n")
        return 0
    except Exception as err:
        sys.stderr.write(f"Error generating report: {err}\n")
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse default exit on error is 2 in modern Python, but help is 0
        return e.code if isinstance(e.code, int) else 2

    try:
        if args.command == "verify":
            return cmd_verify(args)
        elif args.command == "replay":
            return cmd_replay(args)
        elif args.command == "events":
            return cmd_events(args)
        elif args.command == "report":
            return cmd_report(args)
        else:
            parser.print_help(sys.stderr)
            return 2
    except Exception as err:
        sys.stderr.write(f"Fatal error: {err}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())

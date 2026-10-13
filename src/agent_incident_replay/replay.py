"""Read-only incident replay engine for Agent Incident Replay.

Provides chronological, forensic-grade playback of recorded incident sessions
without triggering external actions or modifying the event log.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from agent_incident_replay.events import IncidentEvent
from agent_incident_replay.verifier import IncidentVerifier, VerificationResult


class IncidentReplayer:
    """Replays an incident session in a strictly read-only manner."""

    def __init__(self, verifier: IncidentVerifier | None = None) -> None:
        self.verifier = verifier or IncidentVerifier()

    def load_and_verify(
        self,
        session_id: str,
        storage_dir: Path | str | None = None,
    ) -> tuple[VerificationResult, list[IncidentEvent]]:
        """Load and verify events for a session, returning the result and event list."""
        result = self.verifier.verify_session(session_id, storage_dir=storage_dir)
        return result, result.events

    def format_event(self, event: IncidentEvent) -> list[str]:
        """Format a single event into readable lines."""
        lines = [
            f"+-- [Step {event.sequence}] {event.event_type} " + "-" * max(10, 50 - len(event.event_type)),
            f"|  Sequence:   {event.sequence}",
            f"|  Timestamp:  {event.timestamp}",
            f"|  Prev Hash:  {event.prev_hash[:16]}...{event.prev_hash[-8:]}",
            f"|  Event Hash: {event.hash[:16]}...{event.hash[-8:]}",
            "|  Payload:",
        ]
        if event.payload:
            payload_str = json.dumps(event.payload, indent=2, ensure_ascii=False)
            for pl_line in payload_str.splitlines():
                lines.append(f"|    {pl_line}")
        else:
            lines.append("|    (empty payload)")
        lines.append("+--" + "-" * 60)
        return lines

    def replay(
        self,
        session_id: str,
        storage_dir: Path | str | None = None,
        out: TextIO | None = None,
    ) -> list[str]:
        """Replay all events in an incident session chronologically.

        Args:
            session_id: Session identifier.
            storage_dir: Optional storage directory override.
            out: Optional stream to write replay output to.

        Returns:
            List of formatted lines representing the replay.
        """
        result, events = self.load_and_verify(session_id, storage_dir=storage_dir)

        output_lines: list[str] = [
            "==================================================================",
            f"  AGENT INCIDENT REPLAY: READ-ONLY PLAYBACK FOR '{session_id}'",
            "==================================================================",
            f"Status:      {'VERIFIED (Tamper-evident chain valid)' if result.is_valid else 'INTEGRITY ALERT: Verification failed'}",
            f"Event Count: {len(events)}",
        ]

        if not result.is_valid:
            output_lines.append(f"Warning:     {result.error_message}")

        output_lines.append("------------------------------------------------------------------")

        if not events:
            output_lines.append("No events found in session log.")
        else:
            for event in events:
                output_lines.extend(self.format_event(event))

        output_lines.append("==================================================================")
        output_lines.append("  END OF REPLAY (No external actions performed)")
        output_lines.append("==================================================================")

        if out is not None:
            for line in output_lines:
                out.write(line + "\n")

        return output_lines

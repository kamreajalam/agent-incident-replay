"""Deterministic integrity verifier for Agent Incident Replay session logs.

Verifies SHA-256 hash chaining, sequential ordering, timestamp conformance,
and payload integrity across all recorded events. Identifies the specific
event and sequence where tampering or corruption occurred.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from agent_incident_replay.events import (
    GENESIS_PREV_HASH,
    IncidentEvent,
    InvalidEventError,
    validate_utc_timestamp,
)
from agent_incident_replay.recorder import get_session_path, get_storage_dir


@dataclass
class VerificationResult:
    """Outcome of verifying a session event log."""

    is_valid: bool
    session_id: str
    event_count: int = 0
    error_message: str | None = None
    failed_sequence: int | None = None
    failed_event_type: str | None = None
    head_hash: str | None = None
    root_hash: str | None = None
    events: list[IncidentEvent] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable verification summary."""
        if self.is_valid:
            return (
                f"VERIFICATION PASSED: Session '{self.session_id}' is intact. "
                f"Verified {self.event_count} events. Head hash: {self.head_hash}"
            )
        loc = f" at sequence {self.failed_sequence}" if self.failed_sequence is not None else ""
        ev = f" ({self.failed_event_type})" if self.failed_event_type is not None else ""
        return f"VERIFICATION FAILED{loc}{ev}: {self.error_message}"


class IncidentVerifier:
    """Verifies the cryptographic integrity and structure of an incident session log."""

    @staticmethod
    def verify_file(file_path: Path | str, expected_session_id: str | None = None) -> VerificationResult:
        """Verify the integrity of a session JSONL file directly by path."""
        path = Path(file_path)
        if not path.exists():
            session_id = expected_session_id or path.stem
            return VerificationResult(
                is_valid=False,
                session_id=session_id,
                event_count=0,
                error_message=f"Session file not found at: {path}",
            )

        events: list[IncidentEvent] = []
        expected_seq = 1
        expected_prev_hash = GENESIS_PREV_HASH
        resolved_session_id = expected_session_id or path.stem

        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception as err:
            return VerificationResult(
                is_valid=False,
                session_id=resolved_session_id,
                error_message=f"Failed to read session file: {err}",
            )

        if not lines:
            return VerificationResult(
                is_valid=False,
                session_id=resolved_session_id,
                error_message="Session log is empty (no events recorded).",
            )

        for line_idx, line in enumerate(lines, start=1):
            try:
                event_data = json.loads(line)
            except json.JSONDecodeError as err:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=expected_seq,
                    error_message=f"Corrupt JSON at line {line_idx}: {err}",
                )

            try:
                event = IncidentEvent.from_dict(event_data)
            except (InvalidEventError, KeyError, TypeError) as err:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event_data.get("sequence", expected_seq) if isinstance(event_data, dict) else expected_seq,
                    failed_event_type=event_data.get("event_type") if isinstance(event_data, dict) else None,
                    error_message=f"Invalid event structure at line {line_idx}: {err}",
                )

            # Check session_id consistency
            if event.session_id != resolved_session_id:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event.sequence,
                    failed_event_type=event.event_type,
                    error_message=(
                        f"Session ID mismatch at sequence {event.sequence}: "
                        f"expected '{resolved_session_id}', found '{event.session_id}'"
                    ),
                )

            # Check sequence continuity
            if event.sequence != expected_seq:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event.sequence,
                    failed_event_type=event.event_type,
                    error_message=(
                        f"Sequence discontinuity: expected sequence {expected_seq}, "
                        f"found {event.sequence}"
                    ),
                )

            # Check UTC timestamp format
            if not validate_utc_timestamp(event.timestamp):
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event.sequence,
                    failed_event_type=event.event_type,
                    error_message=(
                        f"Timestamp format invalid at sequence {event.sequence}: "
                        f"'{event.timestamp}' must be ISO-8601 UTC ending in 'Z'"
                    ),
                )

            # Check chain link (prev_hash)
            if event.prev_hash != expected_prev_hash:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event.sequence,
                    failed_event_type=event.event_type,
                    error_message=(
                        f"Broken hash chain at sequence {event.sequence}: "
                        f"prev_hash '{event.prev_hash}' does not match expected '{expected_prev_hash}'"
                    ),
                )

            # Check cryptographic hash self-consistency
            computed_hash = event.compute_hash()
            if event.hash != computed_hash:
                return VerificationResult(
                    is_valid=False,
                    session_id=resolved_session_id,
                    event_count=len(events),
                    failed_sequence=event.sequence,
                    failed_event_type=event.event_type,
                    error_message=(
                        f"Integrity check failed: hash mismatch at sequence {event.sequence} "
                        f"(stored: '{event.hash}', computed: '{computed_hash}')"
                    ),
                )

            events.append(event)
            expected_prev_hash = event.hash
            expected_seq += 1

        return VerificationResult(
            is_valid=True,
            session_id=resolved_session_id,
            event_count=len(events),
            head_hash=events[-1].hash if events else None,
            root_hash=events[0].hash if events else None,
            events=events,
        )

    @classmethod
    def verify_session(
        cls,
        session_id: str,
        storage_dir: Path | str | None = None,
    ) -> VerificationResult:
        """Verify a session by its identifier in the configured storage directory."""
        clean_id = session_id[:-6] if session_id.endswith(".jsonl") else session_id
        session_path = get_session_path(clean_id, storage_dir)
        return cls.verify_file(session_path, expected_session_id=clean_id)

"""Evidence session recorder for appending tamper-evident JSONL events.

Evidence logs are written sequentially to JSONL files.
Each event is linked to its predecessor via SHA-256 chaining.
Existing sessions are never silently overwritten.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agent_incident_replay.events import (
    GENESIS_PREV_HASH,
    IncidentEvent,
    format_utc_timestamp,
)


def get_storage_dir(override: Path | str | None = None) -> Path:
    """Resolve base storage directory from override, env var, or user home."""
    if override is not None:
        return Path(override).expanduser().resolve()
    env_home = os.environ.get("AGENT_INCIDENT_REPLAY_HOME")
    if env_home:
        return Path(env_home).expanduser().resolve()
    return (Path.home() / ".agent-incident-replay").resolve()


def get_sessions_dir(storage_dir: Path | str | None = None) -> Path:
    """Get the directory containing session JSONL files."""
    return get_storage_dir(storage_dir) / "sessions"


def get_reports_dir(storage_dir: Path | str | None = None) -> Path:
    """Get the directory containing markdown forensic reports."""
    return get_storage_dir(storage_dir) / "reports"


def get_session_path(session_id: str, storage_dir: Path | str | None = None) -> Path:
    """Resolve file path for a session JSONL file."""
    clean_id = session_id[:-6] if session_id.endswith(".jsonl") else session_id
    return get_sessions_dir(storage_dir) / f"{clean_id}.jsonl"


class SessionAlreadyExistsError(FileExistsError):
    """Raised when attempting to create a session that already exists."""


class SessionRecorder:
    """Records an ordered sequence of events into a tamper-evident JSONL session log."""

    def __init__(
        self,
        session_id: str,
        storage_dir: Path | str | None = None,
        allow_overwrite: bool = False,
    ) -> None:
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string.")

        self.session_id = session_id[:-6] if session_id.endswith(".jsonl") else session_id
        self.storage_dir = get_storage_dir(storage_dir)
        self.sessions_dir = get_sessions_dir(self.storage_dir)
        self.session_path = get_session_path(self.session_id, self.storage_dir)

        if self.session_path.exists() and not allow_overwrite:
            raise SessionAlreadyExistsError(
                f"Session '{self.session_id}' already exists at {self.session_path}. "
                "Silent overwriting of existing sessions is prohibited to prevent evidence loss."
            )

        self.sessions_dir.mkdir(parents=True, exist_ok=True)

        self._events: list[IncidentEvent] = []
        self._current_hash: str = GENESIS_PREV_HASH

        # If overwriting explicitly, truncate existing file
        if allow_overwrite and self.session_path.exists():
            self.session_path.write_text("", encoding="utf-8")

    @property
    def current_hash(self) -> str:
        """The SHA-256 hash of the most recently recorded event, or genesis hash if none."""
        return self._current_hash

    @property
    def event_count(self) -> int:
        """Total number of recorded events in this session."""
        return len(self._events)

    @property
    def events(self) -> list[IncidentEvent]:
        """A copy of all recorded events in this session."""
        return list(self._events)

    def record(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> IncidentEvent:
        """Record an event, compute its hash linked to the previous event, and append to JSONL.

        Args:
            event_type: Category of the event (e.g. ACTION_PROPOSED, POLICY_DECISION).
            payload: Contextual metadata for the event.
            timestamp: Optional UTC timestamp (defaults to current UTC time ending in 'Z').

        Returns:
            The recorded IncidentEvent instance.
        """
        sequence = len(self._events) + 1
        ts = timestamp if timestamp is not None else format_utc_timestamp()
        p = payload if payload is not None else {}

        event = IncidentEvent.create(
            session_id=self.session_id,
            sequence=sequence,
            event_type=event_type,
            payload=p,
            prev_hash=self._current_hash,
            timestamp=ts,
        )

        # Append to JSONL file immediately
        with open(self.session_path, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")

        self._events.append(event)
        self._current_hash = event.hash
        return event

    def record_action_proposed(
        self,
        action: str,
        parameters: dict[str, Any] | None = None,
        proposed_by: str | None = None,
        **extra: Any,
    ) -> IncidentEvent:
        """Record an ACTION_PROPOSED event."""
        payload: dict[str, Any] = {"action": action}
        if parameters:
            payload["parameters"] = parameters
        if proposed_by:
            payload["proposed_by"] = proposed_by
        payload.update(extra)
        return self.record("ACTION_PROPOSED", payload)

    def record_policy_decision(
        self,
        decision: str,
        rule_id: str | None = None,
        reason: str | None = None,
        **extra: Any,
    ) -> IncidentEvent:
        """Record a POLICY_DECISION event (e.g., ALLOW, BLOCK)."""
        payload: dict[str, Any] = {"decision": decision}
        if rule_id:
            payload["rule_id"] = rule_id
        if reason:
            payload["reason"] = reason
        payload.update(extra)
        return self.record("POLICY_DECISION", payload)

    def record_execution_result(
        self,
        status: str,
        external_effect: str = "NOT_INDEPENDENTLY_VERIFIED",
        **extra: Any,
    ) -> IncidentEvent:
        """Record an EXECUTION_RESULT event."""
        payload: dict[str, Any] = {
            "status": status,
            "external_effect": external_effect,
        }
        payload.update(extra)
        return self.record("EXECUTION_RESULT", payload)

    def record_incident_closed(
        self,
        resolution: str,
        external_effect_status: str = "NOT_INDEPENDENTLY_VERIFIED",
        **extra: Any,
    ) -> IncidentEvent:
        """Record an INCIDENT_CLOSED event."""
        payload: dict[str, Any] = {
            "resolution": resolution,
            "external_effect_status": external_effect_status,
        }
        payload.update(extra)
        return self.record("INCIDENT_CLOSED", payload)

"""Core event definitions, canonical serialization, and SHA-256 hashing.

This module provides tamper-evident event structures for AI agent forensic logging.
Note: Local SHA-256 chaining is tamper-evident (detects modifications or reordering),
but is not tamper-proof and does not by itself prove digital authenticity without
external signatures or anchors.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

GENESIS_PREV_HASH: str = "0" * 64
UTC_TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


class EventError(Exception):
    """Base exception for event errors."""


class InvalidEventError(EventError, ValueError):
    """Raised when an event structure or field is invalid."""


def canonical_json(data: Any) -> str:
    """Serialize data into deterministic, canonical JSON format.

    Uses sorted keys, compact separators without whitespace, and preserved UTF-8 characters.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def format_utc_timestamp(dt: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp string ending in 'Z'."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_utc_timestamp(ts: str) -> bool:
    """Validate that a timestamp conforms to ISO-8601 UTC ending in 'Z'."""
    if not isinstance(ts, str) or not ts.endswith("Z"):
        return False
    return bool(UTC_TIMESTAMP_REGEX.match(ts))


def compute_sha256(canonical_content: str) -> str:
    """Compute SHA-256 hexadecimal digest for canonical string content."""
    return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IncidentEvent:
    """Represents a single immutable event in the incident audit trail.

    Attributes:
        session_id: Unique identifier of the incident recording session.
        sequence: 1-based sequential index of the event in this session.
        timestamp: Canonical UTC timestamp string ending with 'Z'.
        event_type: Category/type of event (e.g. ACTION_PROPOSED, POLICY_DECISION).
        payload: Event-specific metadata and context dictionary.
        prev_hash: SHA-256 hash of the preceding event (or GENESIS_PREV_HASH).
        hash: SHA-256 hash of this event's canonical fields (excluding 'hash').
    """

    session_id: str
    sequence: int
    timestamp: str
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_PREV_HASH
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.session_id or not isinstance(self.session_id, str):
            raise InvalidEventError("session_id must be a non-empty string.")
        if not isinstance(self.sequence, int) or self.sequence < 1:
            raise InvalidEventError(f"sequence must be a positive integer >= 1, got {self.sequence}.")
        if not validate_utc_timestamp(self.timestamp):
            raise InvalidEventError(f"timestamp must be a UTC ISO-8601 string ending in 'Z', got '{self.timestamp}'.")
        if not self.event_type or not isinstance(self.event_type, str):
            raise InvalidEventError("event_type must be a non-empty string.")
        if not isinstance(self.payload, dict):
            raise InvalidEventError("payload must be a dictionary.")
        if not isinstance(self.prev_hash, str) or len(self.prev_hash) != 64:
            raise InvalidEventError("prev_hash must be a 64-character hexadecimal string.")

    def content_dict(self) -> dict[str, Any]:
        """Return the dictionary of fields included in the cryptographic hash."""
        return {
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "sequence": self.sequence,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
        }

    def compute_hash(self) -> str:
        """Calculate the SHA-256 digest of this event's canonical content."""
        canonical_str = canonical_json(self.content_dict())
        return compute_sha256(canonical_str)

    def verify_hash(self) -> bool:
        """Check if the stored hash matches the newly computed hash."""
        return bool(self.hash and self.hash == self.compute_hash())

    def to_dict(self) -> dict[str, Any]:
        """Convert the entire event including its hash into a dictionary."""
        d = self.content_dict()
        d["hash"] = self.hash
        return d

    def to_json(self) -> str:
        """Convert the full event into a canonical JSON string."""
        return canonical_json(self.to_dict())

    @classmethod
    def create(
        cls,
        session_id: str,
        sequence: int,
        event_type: str,
        payload: dict[str, Any] | None = None,
        prev_hash: str = GENESIS_PREV_HASH,
        timestamp: str | None = None,
    ) -> IncidentEvent:
        """Factory method to construct an event and compute its hash."""
        ts = timestamp if timestamp is not None else format_utc_timestamp()
        p = payload if payload is not None else {}
        pre_event = cls(
            session_id=session_id,
            sequence=sequence,
            timestamp=ts,
            event_type=event_type,
            payload=p,
            prev_hash=prev_hash,
            hash="",
        )
        calculated_hash = pre_event.compute_hash()
        return cls(
            session_id=session_id,
            sequence=sequence,
            timestamp=ts,
            event_type=event_type,
            payload=p,
            prev_hash=prev_hash,
            hash=calculated_hash,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentEvent:
        """Instantiate an IncidentEvent from a dictionary."""
        required = {"session_id", "sequence", "timestamp", "event_type", "payload", "prev_hash", "hash"}
        missing = required - set(data.keys())
        if missing:
            raise InvalidEventError(f"Missing required event field(s): {sorted(missing)}")
        return cls(
            session_id=data["session_id"],
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            payload=data["payload"],
            prev_hash=data["prev_hash"],
            hash=data["hash"],
        )

    @classmethod
    def from_json(cls, line: str) -> IncidentEvent:
        """Parse a JSON string into an IncidentEvent."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError as err:
            raise InvalidEventError(f"Failed to parse event JSON: {err}") from err
        if not isinstance(data, dict):
            raise InvalidEventError("Parsed JSON must be an object dictionary.")
        return cls.from_dict(data)

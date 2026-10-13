"""Agent Incident Replay.

Tamper-evident forensic logging, integrity verification, and replay for AI agents.
"""

from agent_incident_replay.events import (
    GENESIS_PREV_HASH,
    IncidentEvent,
    InvalidEventError,
    canonical_json,
    compute_sha256,
    format_utc_timestamp,
    validate_utc_timestamp,
)
from agent_incident_replay.recorder import (
    SessionAlreadyExistsError,
    SessionRecorder,
    get_reports_dir,
    get_session_path,
    get_sessions_dir,
    get_storage_dir,
)
from agent_incident_replay.verifier import (
    IncidentVerifier,
    VerificationResult,
)
from agent_incident_replay.replay import (
    IncidentReplayer,
)
from agent_incident_replay.report import (
    IncidentReporter,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "GENESIS_PREV_HASH",
    "IncidentEvent",
    "InvalidEventError",
    "canonical_json",
    "compute_sha256",
    "format_utc_timestamp",
    "validate_utc_timestamp",
    "SessionAlreadyExistsError",
    "SessionRecorder",
    "get_storage_dir",
    "get_sessions_dir",
    "get_reports_dir",
    "get_session_path",
    "IncidentVerifier",
    "VerificationResult",
    "IncidentReplayer",
    "IncidentReporter",
]

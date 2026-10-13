# Agent Incident Replay

Tamper-evident forensic logging, integrity verification, and incident replay for autonomous AI agents.

## Overview

**Agent Incident Replay** is an independent, lightweight forensic evidence toolkit for AI agents. When autonomous agents make high-stakes operational or financial decisions, operators need deterministic, tamper-evident logs to reconstruct what happened, verify guardrail interventions, and assess external side effects.

Agent Incident Replay provides:
- **Zero Runtime Dependencies**: Built entirely on the Python standard library.
- **JSONL Persistence**: Linear, inspectable append-only event streams.
- **Cryptographic Hash Chaining**: Deterministic SHA-256 chaining across all canonical event data.
- **Deterministic Integrity Verification**: Pinpoints the exact event sequence where any modification or reordering occurred.
- **Read-Only Incident Replay**: Chronological step-by-step playback without side-effects.
- **Forensic Markdown Reporting**: Comprehensive audit summaries covering timeline, policy evaluations, execution results, missing multi-party evidence, and limitations.
- **CLI & Python API**: Unified command-line interface and modular Python SDK.

## Security & Forensic Model

> **Notice:** Agent Incident Replay provides tamper-evident local evidence: it detects modification or reordering of recorded events. It does not by itself prove authenticity, prevent deletion, or protect against an attacker who can rewrite the entire log and its anchor.

### Key Forensic Distinctions
- **Tamper-Evident, Not Tamper-Proof**: Modifying, deleting, inserting, or reordering any event invalidates the SHA-256 cryptographic hash chain and is immediately flagged by the verifier. However, a local adversary with full filesystem write privileges could generate a completely fresh forged chain unless the head hash is anchored externally.
- **Local vs. External Multi-Party Evidence**: An `EXECUTION_RESULT` status of `NOT_EXECUTED` indicates that the local agent controller suppressed execution. This status is designated as `NOT_INDEPENDENTLY_VERIFIED` unless corroborated by independent third-party evidence (such as payment gateway receipts, bank statements, or TLS packet captures).

## Architecture & Storage

Evidence is stored as line-delimited JSON (`JSONL`) files in:
```text
~/.agent-incident-replay/sessions/<session_id>.jsonl
```
Generated reports are stored in:
```text
~/.agent-incident-replay/reports/<session_id>.md
```

Storage directory configuration:
- By default: `~/.agent-incident-replay`
- Environment variable override: `AGENT_INCIDENT_REPLAY_HOME`
- CLI flag override: `--home <path>`

To prevent accidental evidence loss, existing sessions are **never silently overwritten**. Attempting to record to an existing session without explicit overwrite authorization raises `SessionAlreadyExistsError`.

### Event Structure
Each event contains:
```json
{
  "event_type": "POLICY_DECISION",
  "payload": {
    "decision": "BLOCK",
    "reason": "Requested refund exceeds automatic approval limit"
  },
  "prev_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sequence": 2,
  "session_id": "run_001",
  "timestamp": "2026-10-14T02:20:00Z",
  "hash": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
}
```
- **Sequence**: 1-based strictly increasing sequence counter.
- **Timestamp**: Canonical UTC ISO-8601 string ending in `Z`.
- **Prev Hash**: 64-character SHA-256 hex digest of previous event (or 64 zeros for the genesis event).
- **Hash**: SHA-256 hex digest computed over canonical JSON representation of event attributes (excluding `hash`).

## Installation

Install in editable mode with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

## Quick Start & Demo

Run the included AI refund agent scenario:

```bash
python demo.py
```

This simulates an AI refund agent processing a ₹5,000 refund with an automatic approval threshold of ₹500:
1. `ACTION_PROPOSED`: Agent proposes ₹5,000 refund.
2. `POLICY_DECISION`: Guardrail triggers `BLOCK` (exceeds ₹500 limit).
3. `EXECUTION_RESULT`: Execution status `NOT_EXECUTED` (external effect `NOT_INDEPENDENTLY_VERIFIED`).
4. `INCIDENT_CLOSED`: Incident escalated to human supervisor.

## CLI Usage

The package provides the `agent-incident-replay` command:

### 1. Verify Event Integrity
Verify cryptographic integrity and hash chain continuity:
```bash
agent-incident-replay verify run_001
```
Exit code:
- `0`: Valid, intact log.
- `1`: Tampering or corruption detected.
- `2`: Session file not found or command error.

### 2. Read-Only Incident Replay
Step-by-step chronological playback:
```bash
agent-incident-replay replay run_001
```

### 3. Inspect Events
List all recorded events in tabular or raw JSONL format:
```bash
agent-incident-replay events run_001
agent-incident-replay events run_001 --json
```

### 4. Generate Forensic Report
Generate an audit-ready Markdown report:
```bash
agent-incident-replay report run_001
```
The report is saved to `~/.agent-incident-replay/reports/run_001.md`. Report generation is strictly read-only with respect to the session log and does not modify the event chain or timestamps.

## Python API Example

```python
from agent_incident_replay import (
    SessionRecorder,
    IncidentVerifier,
    IncidentReplayer,
    IncidentReporter,
)

# 1. Record events
recorder = SessionRecorder(session_id="run_002")
recorder.record_action_proposed(
    action="issue_refund",
    parameters={"amount": 5000, "currency": "INR"}
)
recorder.record_policy_decision(
    decision="BLOCK",
    reason="Limit exceeded"
)
recorder.record_execution_result(
    status="NOT_EXECUTED",
    external_effect="NOT_INDEPENDENTLY_VERIFIED"
)
recorder.record_incident_closed(resolution="CLOSED_BLOCKED")

# 2. Verify integrity
verifier = IncidentVerifier()
result = verifier.verify_session("run_002")
assert result.is_valid is True

# 3. Generate report
reporter = IncidentReporter()
report_path = reporter.generate_report("run_002")
print(f"Report saved to: {report_path}")
```

## Running Tests

Execute test suite via pytest:

```bash
python -m pytest -q
```

## License

MIT

"""Forensic Markdown report generator for Agent Incident Replay sessions.

Generates audit-ready forensic reports capturing verification status, incident
timeline, policy decisions, execution results, external-effect evidence gaps,
and security limitations. Report generation is read-only with respect to the
event log and does not alter the original hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_incident_replay.events import format_utc_timestamp
from agent_incident_replay.recorder import get_reports_dir, get_storage_dir
from agent_incident_replay.verifier import IncidentVerifier, VerificationResult


class IncidentReporter:
    """Generates markdown forensic reports from incident session logs."""

    def __init__(self, verifier: IncidentVerifier | None = None) -> None:
        self.verifier = verifier or IncidentVerifier()

    def generate_report(
        self,
        session_id: str,
        storage_dir: Path | str | None = None,
    ) -> Path:
        """Generate a forensic Markdown report for a session.

        Args:
            session_id: Session identifier.
            storage_dir: Optional storage directory override.

        Returns:
            Path to the generated markdown report file.
        """
        clean_id = session_id[:-6] if session_id.endswith(".jsonl") else session_id
        resolved_storage = get_storage_dir(storage_dir)
        reports_dir = get_reports_dir(resolved_storage)
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / f"{clean_id}.md"

        # Strictly read-only verification of the session log
        result: VerificationResult = self.verifier.verify_session(clean_id, storage_dir=resolved_storage)

        markdown_content = self._build_markdown(clean_id, result)
        report_path.write_text(markdown_content, encoding="utf-8")
        return report_path

    def _build_markdown(self, session_id: str, result: VerificationResult) -> str:
        report_generated_at = format_utc_timestamp()
        events = result.events

        # Extract key event payloads
        action_proposed: dict[str, Any] | None = None
        policy_decision: dict[str, Any] | None = None
        execution_result: dict[str, Any] | None = None
        incident_closed: dict[str, Any] | None = None

        for ev in events:
            if ev.event_type == "ACTION_PROPOSED" and action_proposed is None:
                action_proposed = ev.payload
            elif ev.event_type == "POLICY_DECISION" and policy_decision is None:
                policy_decision = ev.payload
            elif ev.event_type == "EXECUTION_RESULT" and execution_result is None:
                execution_result = ev.payload
            elif ev.event_type == "INCIDENT_CLOSED" and incident_closed is None:
                incident_closed = ev.payload

        policy_val = policy_decision.get("decision", "NOT_RECORDED") if policy_decision else "NOT_RECORDED"
        exec_val = execution_result.get("status", "NOT_RECORDED") if execution_result else "NOT_RECORDED"
        ext_effect_val = (
            execution_result.get("external_effect", "NOT_INDEPENDENTLY_VERIFIED")
            if execution_result
            else "NOT_INDEPENDENTLY_VERIFIED"
        )

        md: list[str] = [
            f"# Forensic Incident Report: {session_id}",
            "",
            f"**Report Generated (UTC):** `{report_generated_at}`  ",
            f"**Session Identifier:** `{session_id}`  ",
            f"**Integrity Verification:** `{'PASSED' if result.is_valid else 'FAILED'}`  ",
            f"**Total Events Recorded:** `{result.event_count}`  ",
            f"**Cryptographic Head Hash:** `{result.head_hash or 'N/A'}`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "| Parameter | Forensic Value | Description |",
            "| :--- | :--- | :--- |",
            f"| **Session ID** | `{session_id}` | Incident session identifier |",
            f"| **Verification Result** | `{'VALID (Intact SHA-256 chain)' if result.is_valid else 'INVALID / CORRUPTED'}` | Cryptographic chain check |",
            f"| **Policy Decision** | `{policy_val}` | Automated policy evaluation result |",
            f"| **Execution Result** | `{exec_val}` | Runtime execution disposition |",
            f"| **External Effect Status** | `{ext_effect_val}` | Status of independent external confirmation |",
            "",
        ]

        if not result.is_valid:
            md.extend([
                "### Integrity Verification Alert",
                "",
                f"> **Warning:** Cryptographic integrity verification failed for this session.",
                f"> **Failure Reason:** {result.error_message}",
                f"> **Affected Sequence:** {result.failed_sequence or 'Unknown'}",
                "",
            ])

        # Timeline
        md.extend([
            "## 2. Incident Timeline",
            "",
            "| Seq | Timestamp (UTC) | Event Type | Summary / Context | SHA-256 Digest (Prefix) |",
            "| :---: | :--- | :--- | :--- | :--- |",
        ])

        if not events:
            md.append("| - | - | *(No events found)* | - | - |")
        else:
            for ev in events:
                summary_items = []
                for k, v in ev.payload.items():
                    if isinstance(v, (str, int, float, bool)):
                        summary_items.append(f"{k}={v}")
                summary_str = ", ".join(summary_items[:3]) if summary_items else "-"
                md.append(
                    f"| {ev.sequence} | `{ev.timestamp}` | `{ev.event_type}` | {summary_str} | `{ev.hash[:16]}...` |"
                )

        # Policy & Execution Details
        md.extend([
            "",
            "## 3. Governance and Execution Breakdown",
            "",
            "### Policy Decision",
            f"- **Decision:** `{policy_val}`",
        ])
        if policy_decision:
            for k, v in policy_decision.items():
                if k != "decision":
                    md.append(f"- **{k}:** `{v}`")
        else:
            md.append("- *(No policy decision event was recorded)*")

        md.extend([
            "",
            "### Execution Result",
            f"- **Execution Status:** `{exec_val}`",
            f"- **External Effect Indicator:** `{ext_effect_val}`",
        ])
        if execution_result:
            for k, v in execution_result.items():
                if k not in ("status", "external_effect"):
                    md.append(f"- **{k}:** `{v}`")
        else:
            md.append("- *(No execution result event was recorded)*")

        # Missing Evidence Section
        md.extend([
            "",
            "## 4. Evidence Corroboration & Missing Evidence",
            "",
            "The following external corroborating records are currently absent from this local evidence packet:",
            "",
            "1. **Independent Third-Party Gateway Logs:** No cryptographically signed response receipt from an external payment gateway or external financial settlement provider is present.",
            "2. **Independent Bank / Ledger Settlement Confirmation:** No bank statement, mirror ledger confirmation, or double-entry settlement record has been corroborated.",
            "3. **External Network Capture (PCAP/TLS Ingress-Egress):** No raw packet capture or certified TLS egress record exists to independently prove that outbound HTTP calls were suppressed.",
            "4. **External Time-Stamping Authority (RFC 3161):** The timestamps in this log are system-clock derived and have not been notarized by an external TSA or blockchain anchor.",
            "",
            "## 5. Security & Forensic Limitations",
            "",
            "Agent Incident Replay provides tamper-evident local evidence: it detects modification or reordering of recorded events. It does not by itself prove authenticity, prevent deletion, or protect against an attacker who can rewrite the entire log and its anchor.",
            "",
            "Key forensic caveats:",
            "- **Tamper-Evident, Not Tamper-Proof:** Any change to an existing log breaks the cryptographic hash chain. However, an attacker with write access to the local filesystem could recalculate a forged chain from scratch unless the head hash is anchored externally.",
            "- **Non-Execution Verification:** An `EXECUTION_RESULT` of `NOT_EXECUTED` denotes that the local agent controller aborted execution. It is categorized as `NOT_INDEPENDENTLY_VERIFIED` because external counterparties were not queried to substantiate the lack of side effects.",
            "- **Scope:** This report reflects strictly read-only analysis of local event logs. Report generation does not modify original event logs or recalculate log hashes.",
            "",
        ])

        return "\n".join(md)

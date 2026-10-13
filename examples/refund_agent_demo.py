"""Example script demonstrating programmatic usage of Agent Incident Replay.

This script records a policy block scenario, verifies the evidence log, and generates
a forensic markdown report.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_incident_replay import (
    IncidentReporter,
    IncidentReplayer,
    IncidentVerifier,
    SessionRecorder,
)


def main() -> None:
    # Use a temporary directory for this self-contained example
    with tempfile.TemporaryDirectory() as temp_dir:
        storage_path = Path(temp_dir)
        session_id = "refund_incident_001"

        print(f"1. Recording incident session '{session_id}' in {storage_path}...")
        recorder = SessionRecorder(session_id=session_id, storage_dir=storage_path)

        # 1. ACTION_PROPOSED
        recorder.record_action_proposed(
            action="initiate_refund",
            parameters={
                "customer_id": "CUST-774",
                "amount": 5000,
                "currency": "INR",
            },
            proposed_by="refund_agent",
        )

        # 2. POLICY_DECISION
        recorder.record_policy_decision(
            decision="BLOCK",
            rule_id="RULE_REFUND_LIMIT",
            reason="Refund amount 5000 INR exceeds maximum auto-approval threshold 500 INR",
            threshold=500,
        )

        # 3. EXECUTION_RESULT
        recorder.record_execution_result(
            status="NOT_EXECUTED",
            external_effect="NOT_INDEPENDENTLY_VERIFIED",
            details="Aborted by policy guardrail.",
        )

        # 4. INCIDENT_CLOSED
        recorder.record_incident_closed(
            resolution="BLOCKED_BY_POLICY",
            external_effect_status="NOT_INDEPENDENTLY_VERIFIED",
        )

        print(f"Recorded {recorder.event_count} events.")

        # 2. Cryptographic Verification
        print("\n2. Verifying log integrity...")
        verifier = IncidentVerifier()
        result = verifier.verify_session(session_id, storage_dir=storage_path)
        print(f"Is valid: {result.is_valid}")
        print(f"Head hash: {result.head_hash}")

        # 3. Read-only Replay
        print("\n3. Replaying incident (read-only)...")
        replayer = IncidentReplayer()
        lines = replayer.replay(session_id, storage_dir=storage_path)
        for line in lines[:10]:
            print(f"  {line}")
        print("  ...")

        # 4. Forensic Report Generation
        print("\n4. Generating forensic Markdown report...")
        reporter = IncidentReporter()
        report_file = reporter.generate_report(session_id, storage_dir=storage_path)
        print(f"Report written to: {report_file}")
        print(f"Report size: {report_file.stat().st_size} bytes")


if __name__ == "__main__":
    main()

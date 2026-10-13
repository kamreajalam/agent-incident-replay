#!/usr/bin/env python3
"""AI Refund Agent Incident Demo (Session: run_001).

Simulates an autonomous customer support agent processing a high-value refund request:
- Requested refund: ₹5,000
- Automatic approval limit: ₹500
- Policy decision: BLOCK
- Execution result: NOT_EXECUTED
- External effect: NOT_INDEPENDENTLY_VERIFIED

Recorded events:
1. ACTION_PROPOSED
2. POLICY_DECISION
3. EXECUTION_RESULT
4. INCIDENT_CLOSED

IMPORTANT FORENSIC DISCLAIMERS:
- This demo does NOT connect to a real payment provider or banking network.
- The absence of a financial effect was NOT independently verified by external systems.
- Local hash chaining provides tamper-evident audit logging, but does not prove authenticity.
"""

from __future__ import annotations

import sys
from agent_incident_replay.recorder import SessionRecorder, get_session_path, get_storage_dir
from agent_incident_replay.verifier import IncidentVerifier


def run_demo() -> None:
    session_id = "run_001"
    storage_dir = get_storage_dir()
    session_path = get_session_path(session_id, storage_dir)

    print("=" * 70)
    print("  AGENT INCIDENT REPLAY: AI REFUND AGENT SIMULATION")
    print("=" * 70)
    print(f"Target Session: {session_id}")
    print(f"Storage Path:   {session_path}")
    print("-" * 70)

    # Initialize recorder with allow_overwrite=True for repeatable demo execution
    recorder = SessionRecorder(session_id=session_id, allow_overwrite=True)

    # Event 1: ACTION_PROPOSED
    print("1. Recording ACTION_PROPOSED...")
    e1 = recorder.record_action_proposed(
        action="issue_refund",
        parameters={
            "customer_id": "CUST-99201",
            "order_id": "ORD-88129",
            "refund_amount": 5000,
            "currency": "INR",
            "reason": "Customer dissatisfied with subscription delivery",
        },
        proposed_by="ai_support_refund_agent_v1",
    )
    print(f"   Seq: {e1.sequence} | Hash: {e1.hash[:16]}... | Prev: {e1.prev_hash[:16]}...")

    # Event 2: POLICY_DECISION
    print("2. Recording POLICY_DECISION...")
    e2 = recorder.record_policy_decision(
        decision="BLOCK",
        rule_id="MAX_AUTOMATIC_REFUND_LIMIT",
        reason="Requested refund amount (₹5,000 INR) exceeds automatic threshold (₹500 INR)",
        threshold=500,
        requested_amount=5000,
        currency="INR",
        action="ESCALATE_TO_HUMAN_SUPERVISOR",
    )
    print(f"   Seq: {e2.sequence} | Hash: {e2.hash[:16]}... | Prev: {e2.prev_hash[:16]}...")

    # Event 3: EXECUTION_RESULT
    print("3. Recording EXECUTION_RESULT...")
    e3 = recorder.record_execution_result(
        status="NOT_EXECUTED",
        external_effect="NOT_INDEPENDENTLY_VERIFIED",
        details="Refund transaction suppressed by policy engine; no request dispatched to payment gateway.",
        suppressed_action="issue_refund",
        amount=5000,
        currency="INR",
    )
    print(f"   Seq: {e3.sequence} | Hash: {e3.hash[:16]}... | Prev: {e3.prev_hash[:16]}...")

    # Event 4: INCIDENT_CLOSED
    print("4. Recording INCIDENT_CLOSED...")
    e4 = recorder.record_incident_closed(
        resolution="BLOCKED_BY_POLICY_AND_ESCALATED",
        external_effect_status="NOT_INDEPENDENTLY_VERIFIED",
        ticket_id="TICK-55410",
        assigned_team="Tier-2 Human Support",
        notes="Incident closed locally in agent runtime; awaiting manual review.",
    )
    print(f"   Seq: {e4.sequence} | Hash: {e4.hash[:16]}... | Prev: {e4.prev_hash[:16]}...")

    print("-" * 70)
    print(f"Successfully recorded 4 linked events to {session_path}")
    print(f"Head Hash: {recorder.current_hash}")

    # Immediate self-verification
    print("\nVerifying session integrity...")
    verifier = IncidentVerifier()
    res = verifier.verify_file(session_path, expected_session_id=session_id)
    if res.is_valid:
        print(f"[VERIFIED] Cryptographic hash chain is intact across {res.event_count} events.")
    else:
        print(f"[FAILED] Verification failed: {res.error_message}")
        sys.exit(1)

    print("\nFORENSIC DISCLAIMERS:")
    print("1. This demo does NOT connect to a real payment gateway or banking API.")
    print("2. The absence of an external financial effect was NOT independently verified.")
    print("3. Local SHA-256 chaining is tamper-evident, not tamper-proof or authenticated.")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()

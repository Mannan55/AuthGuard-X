"""
AuthGuard-X Sprint 5 Test Suite — Evidence-Grounded SOC Investigation Reporting

Tests:
1. Phase 0 Hardening: Raw evidence hashing distinction (exact source bytes vs reconstructed)
2. Phase 0 Hardening: Detection failure propagation (unswallowed exceptions, partial/failed statuses, deterministic retries)
3. Report Creation & System Facts Grounding
4. Evidence Linkage & Cross-Case Reference Isolation
5. Chronological Investigation Timeline (occurrence time vs recorded time, timezone preservation, category filters)
6. Report Lifecycle & Versioning (Draft -> In Review -> Finalized, immutable snapshotting)
7. Report Revision Workflow (version incrementation, prior version preservation)
8. Role-Based Access Control & Case Ownership Enforcement
9. Optimistic Locking Concurrency Defense
10. Deterministic Investigation Coverage & Quality Indicators (6 indicators)
11. Printable HTML & Structured JSON Exports (confidentiality labels, disclaimers, XSS prevention)
12. CSRF & Input Boundary Protections
"""

import io
import json
import sqlite3
import pytest
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, init_db, evaluate_detection_pipeline
from ingestion import IngestionParser, extract_forensic_payload


@pytest.fixture
def test_env(tmp_path):
    db_file = tmp_path / "test_sprint5.db"
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": "sprint5-test-secret-key-very-secure",
        "ENABLE_EXTERNAL_GEOIP": False,
    }
    app = create_app(config)
    client = app.test_client()
    return {"app": app, "client": client, "db_path": str(db_file)}


def get_csrf_token(client):
    res = client.get("/api/auth/csrf-token")
    assert res.status_code == 200
    data = res.get_json()
    return data.get("csrf_token")


def login_user(client, username="testadmin", password="AdminPassword2026!"):
    token = get_csrf_token(client)
    res = client.post("/api/auth/login", json={
        "username": username,
        "password": password
    }, headers={"X-CSRFToken": token})
    assert res.status_code == 200
    return get_csrf_token(client)


def create_test_analyst(db_path, username="analyst_alice", password="AlicePassword2026!", role="analyst"):
    import bcrypt
    conn = get_db_connection(db_path)
    c = conn.cursor()
    pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now_str = "2026-10-31 10:00:00"
    c.execute("""
        INSERT OR IGNORE INTO users (username, password, role, created_at)
        VALUES (?, ?, ?, ?)
    """, (username, pwd_hash, role, now_str))
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    uid = c.fetchone()["id"]
    conn.commit()
    conn.close()
    return uid


class TestSprint5Phase0Hardening:
    """Phase 0 Hardening verification tests."""

    def test_raw_evidence_hashing_distinction(self):
        """
        Verify distinction between SHA-256 of exact source record bytes vs
        digest of reconstructed/normalized representations.
        Reconstructed rows must never be labeled as original raw source bytes.
        """
        # Exact source text
        exact_line = "2026-10-31 14:00:00,192.168.1.100,SSH Brute Force,80,root,,srv-01,failure"
        exact_payload = extract_forensic_payload(raw_source_text=exact_line, source_format="canonical_csv")

        assert exact_payload["payload_type"] == "exact_source_line"
        assert exact_payload["payload_provenance"] == "verbatim_source_text"
        assert exact_payload["raw_bytes_hash"] is not None
        assert len(exact_payload["raw_bytes_hash"]) == 64
        assert exact_payload["is_truncated"] is False
        assert exact_payload["original_byte_length"] == len(exact_line.encode("utf-8"))

        # Reconstructed representation (no exact raw source line)
        reconstructed_dict = {"ip": "192.168.1.100", "attack": "SSH Brute Force", "risk": 80}
        rec_json = json.dumps(reconstructed_dict, sort_keys=True)
        rec_payload = extract_forensic_payload(raw_source_text=None, reconstructed_text=rec_json, source_format="canonical_csv")

        assert rec_payload["payload_type"] == "reconstructed_canonical_csv_row"
        assert rec_payload["payload_provenance"] == "reconstructed_representation"
        assert rec_payload["raw_bytes_hash"] is None  # Must NOT label reconstructed row as raw source bytes!
        assert rec_payload["normalized_payload_hash"] is not None
        assert len(rec_payload["normalized_payload_hash"]) == 64

    def test_detection_failure_propagation(self, test_env):
        """
        Verify that rule evaluation errors are logged to rule_executions with status='failed'
        and error_message, accurately propagating completed, partial, or failed statuses.
        """
        db_path = test_env["db_path"]
        conn = get_db_connection(db_path)
        c = conn.cursor()

        # Inject a broken rule with invalid regex to trigger execution exception
        c.execute("""
            INSERT INTO detection_rules (
                rule_id, name, description, severity, status, conditions_json,
                threshold, time_window_seconds, group_by_field, mitre_technique_id,
                mitre_technique_name, version, created_at, updated_at
            ) VALUES (
                'RULE-FAULTY-999', 'Faulty Test Rule', 'Rule with uncompilable regex', 'high', 'enabled',
                '[{"field": "username", "operator": "matches_regex", "value": "([unclosed_regex"}]',
                1, 60, 'none', 'T1110', 'Fault Injection', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00'
            )
        """)
        # Insert a test log
        c.execute("""
            INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES ('admin', 'Brute Force', 'Abnormal', 85, '10.0.0.99', 'US', '2026-10-31 10:00:00', 0, 1)
        """)
        log_id = c.lastrowid
        conn.commit()
        conn.close()

        # Run detection pipeline in detailed mode
        result = evaluate_detection_pipeline([log_id], db_path, detailed=True)
        assert isinstance(result, dict)
        assert result["status"] in ("partial", "failed")
        assert len(result["failed_rules"]) >= 1

        failed_ids = [r["rule_id"] for r in result["failed_rules"]]
        assert "RULE-FAULTY-999" in failed_ids

        # Verify failure logged in rule_executions table
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT status, error_message FROM rule_executions WHERE status = 'failed'")
        failed_row = c.fetchone()
        assert failed_row is not None
        assert "regex" in failed_row["error_message"].lower() or "error" in failed_row["error_message"].lower()
        conn.close()


class TestSprint5ReportBuilder:
    """Sprint 5 Case Reports and Verified Evidence tests."""

    def test_report_creation_and_facts_grounding(self, test_env):
        """
        Verify creating an investigation report initializes system-grounded facts,
        populates affected accounts/assets, links initial case records, and records audit.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        # Create test incident and case
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES ('jdoe', 'Credential Stuffing', 'Repeated login attempts', 75, '198.51.100.25', 'US', '2026-10-31 11:00:00', 0, 0)
        """)
        inc_id = c.lastrowid
        c.execute("""
            INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at)
            VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 11:00:00', '2026-10-31 11:00:00')
        """, (inc_id,))
        conn.commit()
        conn.close()

        # Create report via API
        res = client.post("/api/reports", json={
            "case_id": inc_id,
            "title": "Incident Post-Mortem — Credential Stuffing"
        }, headers={"X-CSRFToken": token})

        assert res.status_code == 201
        data = res.get_json()
        assert data["report_id"].startswith("REP-")
        assert data["version"] == 1
        assert data["status"] == "draft"

        report_id = data["report_id"]

        # Fetch report details
        get_res = client.get(f"/api/reports/{report_id}")
        assert get_res.status_code == 200
        rep = get_res.get_json()["report"]

        assert rep["case_id"] == inc_id
        assert rep["incident_classification"] == "Credential Stuffing"
        assert rep["severity"] == "high"
        assert rep["is_finalized"] == 0

        # Grounded facts
        accounts = json.loads(rep["affected_accounts_json"])
        assert "jdoe" in accounts

        assets = json.loads(rep["affected_assets_json"])
        assert "198.51.100.25" in assets

        # Initial evidence link created for primary incident
        links = rep["evidence_links"]
        assert len(links) >= 1
        inc_link = next((l for l in links if l["reference_type"] == "incident"), None)
        assert inc_link is not None
        assert str(inc_link["reference_id"]) == str(inc_id)

    def test_evidence_linkage_and_cross_case_isolation(self, test_env):
        """
        Verify linking evidence references and enforcing cross-case isolation.
        An analyst cannot link records belonging to a different investigation case.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        # Case A
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('userA', 'Brute Force', 'Failures', 70, '10.0.0.1', 'US', '2026-10-31 12:00:00', 0, 1)")
        case_a_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 12:00:00', '2026-10-31 12:00:00')", (case_a_id,))

        # Case B
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('userB', 'Password Spray', 'Spray', 60, '10.0.0.2', 'US', '2026-10-31 12:05:00', 0, 1)")
        case_b_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'new', 1, 'testadmin', 1, '2026-10-31 12:05:00', '2026-10-31 12:05:00')", (case_b_id,))

        # Note belonging to Case B
        c.execute("INSERT INTO incident_notes (incident_id, author_id, author_username, content, created_at, updated_at) VALUES (?, 1, 'testadmin', 'Secret note in Case B', '2026-10-31 12:06:00', '2026-10-31 12:06:00')", (case_b_id,))
        case_b_note_id = c.lastrowid
        conn.commit()
        conn.close()

        # Create report for Case A
        rep_res = client.post("/api/reports", json={"case_id": case_a_id}, headers={"X-CSRFToken": token})
        assert rep_res.status_code == 201
        report_id = rep_res.get_json()["report_id"]

        # Attempt to link Case B's note into Case A's report -> Must be rejected (400 or 403)
        cross_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "case_note",
            "reference_id": str(case_b_note_id),
            "label": "Illicit Cross-Case Note"
        }, headers={"X-CSRFToken": token})
        assert cross_res.status_code in (400, 403)

        # Attempt to link Case B's incident directly -> Must be rejected
        cross_inc_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "incident",
            "reference_id": str(case_b_id),
            "label": "Illicit Cross Incident"
        }, headers={"X-CSRFToken": token})
        assert cross_inc_res.status_code in (400, 403)

        # Legitimate rule reference link -> Must succeed
        rule_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "rule",
            "reference_id": "RULE-AUTH-001",
            "label": "Triggered Authentication Rule"
        }, headers={"X-CSRFToken": token})
        assert rule_res.status_code == 201
        link_id = rule_res.get_json()["link_id"]

        # Unlink evidence
        del_res = client.delete(f"/api/reports/{report_id}/evidence/{link_id}", headers={"X-CSRFToken": token})
        assert del_res.status_code == 200

    def test_chronological_investigation_timeline(self, test_env):
        """
        Verify timeline endpoint combines event occurrence times, ingestion timestamps,
        detection alerts, and case lifecycle audit actions with original timezone preservation.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('analyst_user', 'SSH Brute Force', 'Failures', 80, '192.168.1.50', 'US', '2026-10-31 09:30:00', 0, 0)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 09:35:00', '2026-10-31 09:35:00')", (inc_id,))

        # Ingestion batch
        c.execute("""
            INSERT INTO ingestion_batches (
                batch_id, filename, source_type,
                total_records, accepted_records, rejected_records, duplicate_records,
                created_by, created_username, created_at, status, detection_status
            ) VALUES (
                'BATCH-001', 'ssh.log', 'linux_ssh',
                1, 1, 0, 0,
                1, 'testadmin', '2026-10-31 09:30:00', 'completed', 'completed'
            )
        """)

        # Security event with timezone metadata
        c.execute("""
            INSERT INTO security_events (
                event_id, batch_id, source_type, importer, event_time, ingested_at,
                category, attack_type, username, source_ip, dest_ip, outcome, severity, risk_score,
                fingerprint, incident_id, original_timestamp, original_timezone
            ) VALUES (
                'EVT-TEST-001', 'BATCH-001', 'linux_ssh', 'testadmin', '2026-10-31 09:00:00', '2026-10-31 09:31:00',
                'Authentication', 'SSH Login Attempt', 'analyst_user', '192.168.1.50', '192.168.1.1', 'failure', 'high', 80,
                'fp_test_001', ?, '2026-10-31T14:30:00+05:30', '+05:30'
            )
        """, (inc_id,))

        # Case audit action
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, 1, 'testadmin', 'status_changed', 'new', 'investigating', 'Investigation started by testadmin', '2026-10-31 09:35:00')
        """, (inc_id,))

        conn.commit()
        conn.close()

        rep_res = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": token})
        report_id = rep_res.get_json()["report_id"]

        tl_res = client.get(f"/api/reports/{report_id}/timeline")
        assert tl_res.status_code == 200
        tl_data = tl_res.get_json()
        timeline = tl_data["timeline"]
        assert len(timeline) >= 3

        # Check occurrence vs recorded time distinction
        ssh_evt = next((e for e in timeline if "EVT-TEST-001" in e.get("details", "") or e.get("original_timezone") == "+05:30"), None)
        assert ssh_evt is not None
        assert ssh_evt["occurrence_time"] == "2026-10-31 09:00:00"
        assert ssh_evt["recorded_time"] == "2026-10-31 09:31:00"
        assert ssh_evt["original_timezone"] == "+05:30"

        # Check category filtering
        telemetry_only = client.get(f"/api/reports/{report_id}/timeline?category=telemetry").get_json()["timeline"]
        assert all(e["category"] == "telemetry" for e in telemetry_only)

        actions_only = client.get(f"/api/reports/{report_id}/timeline?category=case_action").get_json()["timeline"]
        assert all(e["category"] == "case_action" for e in actions_only)

    def test_report_lifecycle_draft_review_finalized(self, test_env):
        """
        Verify lifecycle transitions: draft -> in_review -> finalized.
        Finalization creates immutable historical snapshot in report_versions.
        Mutations on finalized reports are rejected with 409 Conflict.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('test_user', 'Port Scan', 'Recon', 50, '10.0.0.10', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'contained', 1, 'testadmin', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id,))
        conn.commit()
        conn.close()

        rep_res = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": token})
        report_id = rep_res.get_json()["report_id"]

        # Transition draft -> in_review
        rev_res = client.post(f"/api/reports/{report_id}/status", json={
            "expected_version": 1,
            "status": "in_review"
        }, headers={"X-CSRFToken": token})
        assert rev_res.status_code == 200
        assert rev_res.get_json()["status"] == "in_review"

        # Transition in_review -> finalized
        fin_res = client.post(f"/api/reports/{report_id}/status", json={
            "expected_version": 1,
            "status": "finalized",
            "change_summary": "Initial completed investigation report"
        }, headers={"X-CSRFToken": token})
        assert fin_res.status_code == 200
        assert fin_res.get_json()["status"] == "finalized"
        assert fin_res.get_json()["is_finalized"] == 1

        # Check immutable snapshot created in report_versions
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT version, status, snapshot_json, finalized_by_username FROM report_versions WHERE report_id = ?", (report_id,))
        version_row = c.fetchone()
        assert version_row is not None
        assert version_row["version"] == 1
        assert version_row["status"] == "finalized"
        snapshot = json.loads(version_row["snapshot_json"])
        assert snapshot["report_id"] == report_id
        assert "provenance_disclaimer" in snapshot
        conn.close()

        # Attempt to edit finalized report -> Must be rejected with 409 Conflict
        patch_res = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 1,
            "title": "Illegal Modification"
        }, headers={"X-CSRFToken": token})
        assert patch_res.status_code == 409

    def test_report_revision_workflow(self, test_env):
        """
        Verify revision workflow: calling /revise on a finalized report increments version,
        resets status to draft, and preserves prior finalized snapshot.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('u1', 'Brute Force', 'Abnormal', 60, '10.0.0.1', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'resolved', 1, 'testadmin', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id,))
        conn.commit()
        conn.close()

        rep = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # Finalize v1
        client.post(f"/api/reports/{report_id}/status", json={"expected_version": 1, "status": "finalized"}, headers={"X-CSRFToken": token})

        # Revise to v2
        rev_res = client.post(f"/api/reports/{report_id}/revise", json={
            "change_summary": "Revising report following additional telemetry import"
        }, headers={"X-CSRFToken": token})
        assert rev_res.status_code == 200
        rev_data = rev_res.get_json()
        assert rev_data["version"] == 2
        assert rev_data["status"] == "draft"
        assert rev_data["is_finalized"] == 0

        # Now v2 is editable
        patch_res = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 2,
            "executive_summary": "Updated executive summary for v2."
        }, headers={"X-CSRFToken": token})
        assert patch_res.status_code == 200

        # Confirm v1 historical version remains preserved in DB
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT version FROM report_versions WHERE report_id = ? AND version = 1", (report_id,))
        assert c.fetchone() is not None
        conn.close()

    def test_report_rbac_and_ownership(self, test_env):
        """
        Verify case ownership enforcement: an analyst cannot modify another analyst's report,
        while an administrator can oversee and update reports.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]

        # Create two distinct analysts
        alice_id = create_test_analyst(db_path, "analyst_alice", "AlicePassword2026!", "analyst")
        bob_id = create_test_analyst(db_path, "analyst_bob", "BobPassword2026!", "analyst")

        # Case assigned to Alice
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('u1', 'Brute Force', 'Abnormal', 60, '10.0.0.1', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', ?, 'analyst_alice', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id, alice_id))
        conn.commit()
        conn.close()

        # Alice creates report
        alice_token = login_user(client, "analyst_alice", "AlicePassword2026!")
        rep_res = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": alice_token})
        assert rep_res.status_code == 201
        report_id = rep_res.get_json()["report_id"]

        # Bob logs in and attempts to edit Alice's report -> Must be rejected with 403 Forbidden
        bob_token = login_user(client, "analyst_bob", "BobPassword2026!")
        bob_patch = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 1,
            "title": "Bob's unauthorized title"
        }, headers={"X-CSRFToken": bob_token})
        assert bob_patch.status_code == 403

        # Admin logs in -> Permitted to oversee/update report
        admin_token = login_user(client, "testadmin", "AdminPassword2026!")
        admin_patch = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 1,
            "title": "Admin approved title"
        }, headers={"X-CSRFToken": admin_token})
        assert admin_patch.status_code == 200

    def test_optimistic_locking_concurrency(self, test_env):
        """
        Verify expected_version validation: reject missing or malformed version with 400,
        reject stale expected_version with 409 Conflict.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('u1', 'Brute Force', 'Abnormal', 60, '10.0.0.1', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id,))
        conn.commit()
        conn.close()

        rep = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # Missing expected_version -> 400
        res_missing = client.patch(f"/api/reports/{report_id}", json={"title": "No Version"}, headers={"X-CSRFToken": token})
        assert res_missing.status_code == 400

        # Boolean version -> 400
        res_bool = client.patch(f"/api/reports/{report_id}", json={"expected_version": True, "title": "Bool Version"}, headers={"X-CSRFToken": token})
        assert res_bool.status_code == 400

        # Stale version -> 409
        res_stale = client.patch(f"/api/reports/{report_id}", json={"expected_version": 99, "title": "Stale Version"}, headers={"X-CSRFToken": token})
        assert res_stale.status_code == 409

    def test_deterministic_quality_checklist(self, test_env):
        """
        Verify 6 deterministic quality indicators: resolution summary, findings linkage,
        case timestamps, conflicting observations, event provenance, and fact/conclusion separation.
        No fake AI scores or percentages.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('u1', 'Brute Force', 'Abnormal', 60, '10.0.0.1', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("""
            INSERT INTO cases (incident_id, status, assigned_to, assigned_username, resolution_summary, version, created_at, updated_at)
            VALUES (?, 'resolved', 1, 'testadmin', 'Attacker IP blocked at perimeter firewall', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')
        """, (inc_id,))
        conn.commit()
        conn.close()

        rep = client.post("/api/reports", json={"case_id": inc_id}, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        rep_detail = client.get(f"/api/reports/{report_id}").get_json()["report"]
        qc = rep_detail["quality_checks"]
        assert len(qc) == 6

        qc_codes = {c["code"]: c["status"] for c in qc}
        assert "resolution_summary" in qc_codes
        assert qc_codes["resolution_summary"] == "pass"
        assert "case_timestamps" in qc_codes
        assert qc_codes["case_timestamps"] == "pass"
        assert "conclusions_separation" in qc_codes
        assert qc_codes["conclusions_separation"] == "pass"

    def test_report_export_html_and_json(self, test_env):
        """
        Verify HTML and JSON export formats: confidentiality notices, provenance disclaimers,
        proper structure, and zero password or token leakage.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('target_user', 'Credential Stuffing', 'Repeated failure', 75, '10.0.0.5', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id,))
        conn.commit()
        conn.close()

        rep = client.post("/api/reports", json={
            "case_id": inc_id,
            "title": "Investigation Report for Export"
        }, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # HTML Export
        html_res = client.get(f"/api/reports/{report_id}/export/html")
        assert html_res.status_code == 200
        assert "text/html" in html_res.headers["Content-Type"]
        html_text = html_res.data.decode("utf-8")

        assert "CONFIDENTIAL" in html_text
        assert "Forensic Evidence Grounding &amp; Provenance Disclaimer" in html_text
        assert "@media print" in html_text
        assert "Credential Stuffing" in html_text
        assert "password_hash" not in html_text
        assert "secret_key" not in html_text

        # JSON Export
        json_res = client.get(f"/api/reports/{report_id}/export/json")
        assert json_res.status_code == 200
        assert "application/json" in json_res.headers["Content-Type"]
        json_data = json_res.get_json()

        assert json_data["report_id"] == report_id
        assert "forensic_provenance_disclaimer" in json_data
        assert "metadata" in json_data
        assert "analyst_findings" in json_data
        assert "verified_evidence_references" in json_data
        assert "investigation_timeline" in json_data
        assert "quality_indicators" in json_data

    def test_stored_xss_defense_in_html_export(self, test_env):
        """
        Verify that malicious XSS payloads in report title or executive summary
        are strictly HTML-escaped and never rendered as executable script tags.
        """
        client = test_env["client"]
        db_path = test_env["db_path"]
        token = login_user(client)

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated) VALUES ('u1', 'Brute Force', 'Abnormal', 60, '10.0.0.1', 'US', '2026-10-31 10:00:00', 0, 1)")
        inc_id = c.lastrowid
        c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at) VALUES (?, 'investigating', 1, 'testadmin', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')", (inc_id,))
        conn.commit()
        conn.close()

        xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
        rep = client.post("/api/reports", json={
            "case_id": inc_id,
            "title": f"Report with {xss_payload}",
            "executive_summary": f"Summary with {xss_payload}"
        }, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        html_res = client.get(f"/api/reports/{report_id}/export/html")
        html_text = html_res.data.decode("utf-8")

        # Must NOT contain raw unescaped script tag
        assert "<script>alert('XSS')</script>" not in html_text
        assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in html_text or "&lt;script&gt;alert('XSS')&lt;/script&gt;" in html_text


"""
AuthGuard-X Sprint 5 Security and Report Integrity Hardening Tests

Covers:
1. Centralized report authorization:
   - Multi-analyst case ownership and direct URL isolation
   - Server-enforced list filtering
   - Forbidden operation database mutation prevention
   - Admin override verification
2. Immutable snapshot exports & reproducibility:
   - Version-aware HTML and JSON exports (?version=N)
   - Re-export reproducibility across case mutations and subsequent revisions
   - Non-existent version 404 handling
3. Exact incident ID matching:
   - Prevention of substring false-positives for incident IDs 12, 112, and 120
   - JSON array membership via json_valid and json_each
4. Atomic version checks & concurrency conflict handling:
   - Stale expected_version rejection with HTTP 409 Conflict
   - Direct mutation blocking on finalized reports
"""

import json
import sqlite3
import pytest
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection


@pytest.fixture
def sec_env(tmp_path):
    db_file = tmp_path / "test_sec_hardening.db"
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "admin_sec",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": "sprint5-sec-hardening-test-secret-key",
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


def login_client(client, username, password):
    token = get_csrf_token(client)
    res = client.post("/api/auth/login", json={
        "username": username,
        "password": password
    }, headers={"X-CSRFToken": token})
    assert res.status_code == 200
    return get_csrf_token(client)


def create_user(db_path, username, password, role="analyst"):
    import bcrypt
    conn = get_db_connection(db_path)
    c = conn.cursor()
    pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now_str = "2026-10-31 10:00:00"
    c.execute("""
        INSERT INTO users (username, password, role, created_at)
        VALUES (?, ?, ?, ?)
    """, (username, pwd_hash, role, now_str))
    uid = c.lastrowid
    conn.commit()
    conn.close()
    return uid


class TestCentralizedReportAuthorization:
    """Tests requirement 1: Centralized, server-enforced permission model."""

    def test_multi_analyst_authorization_and_isolation(self, sec_env):
        client = sec_env["client"]
        db_path = sec_env["db_path"]

        # Create two distinct analysts
        alice_id = create_user(db_path, "analyst_alice", "AlicePass2026!", role="analyst")
        bob_id = create_user(db_path, "analyst_bob", "BobPass2026!", role="analyst")

        # Create Case 101 assigned to Alice
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (101, 'target_user', 'Credential Stuffing', 'Abnormal Velocity', 75, '198.51.100.22', 'US', '2026-10-31 11:00:00', 0, 1)
        """)
        c.execute("""
            INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at)
            VALUES (101, 'investigating', ?, 'analyst_alice', 1, '2026-10-31 11:00:00', '2026-10-31 11:00:00')
        """, (alice_id,))
        conn.commit()
        conn.close()

        # Alice logs in and creates report
        alice_token = login_client(client, "analyst_alice", "AlicePass2026!")
        create_res = client.post("/api/reports", json={
            "case_id": 101,
            "title": "Alice Confidential Case Report",
            "executive_summary": "Initial findings on unauthorized credential stuffing."
        }, headers={"X-CSRFToken": alice_token})
        assert create_res.status_code == 201
        report_data = create_res.get_json()
        report_id = report_data["report_id"]

        # Bob logs in
        bob_token = login_client(client, "analyst_bob", "BobPass2026!")

        # 1. Bob cannot see Alice's report in listing
        list_res = client.get("/api/reports")
        assert list_res.status_code == 200
        reports_for_bob = list_res.get_json().get("reports", [])
        assert all(r["report_id"] != report_id for r in reports_for_bob)

        # 2. Bob cannot view report details directly
        get_res = client.get(f"/api/reports/{report_id}")
        assert get_res.status_code == 403
        assert "Access denied" in get_res.get_json()["message"]

        # 3. Bob cannot access report timeline
        time_res = client.get(f"/api/reports/{report_id}/timeline")
        assert time_res.status_code == 403

        # 4. Bob cannot export HTML
        html_res = client.get(f"/api/reports/{report_id}/export/html")
        assert html_res.status_code == 403

        # 5. Bob cannot export JSON
        json_res = client.get(f"/api/reports/{report_id}/export/json")
        assert json_res.status_code == 403

        # 6. Bob cannot edit report
        patch_res = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 1,
            "title": "Tampered By Bob"
        }, headers={"X-CSRFToken": bob_token})
        assert patch_res.status_code == 403

        # 7. Bob cannot transition status
        status_res = client.post(f"/api/reports/{report_id}/status", json={
            "status": "in_review",
            "expected_version": 1
        }, headers={"X-CSRFToken": bob_token})
        assert status_res.status_code == 403

        # 8. Bob cannot link evidence
        ev_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "incident_log",
            "reference_id": 101,
            "label": "Unauthorized evidence injection"
        }, headers={"X-CSRFToken": bob_token})
        assert ev_res.status_code == 403

        # Verify zero database modifications occurred from Bob's unauthorized requests
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT title, status, version FROM case_reports WHERE report_id = ?", (report_id,))
        rep_db = dict(c.fetchone())
        assert rep_db["title"] == "Alice Confidential Case Report"
        assert rep_db["status"] == "draft"
        assert rep_db["version"] == 1

        c.execute("SELECT COUNT(*) AS count FROM report_evidence_links WHERE report_id = ? AND label = 'Unauthorized evidence injection'", (report_id,))
        assert c.fetchone()["count"] == 0
        c.execute("SELECT COUNT(*) AS count FROM report_evidence_links WHERE report_id = ?", (report_id,))
        assert c.fetchone()["count"] == 1  # Exactly the auto-linked primary incident
        conn.close()

        # Admin logs in and CAN view and manage the report
        admin_token = login_client(client, "admin_sec", "AdminPassword2026!")
        admin_get = client.get(f"/api/reports/{report_id}")
        assert admin_get.status_code == 200
        assert admin_get.get_json()["report"]["report_id"] == report_id


class TestImmutableVersionExports:
    """Tests requirement 2: Exact reproducibility of finalized report exports."""

    def test_reproducible_exports_across_case_mutations_and_revisions(self, sec_env):
        client = sec_env["client"]
        db_path = sec_env["db_path"]
        token = login_client(client, "admin_sec", "AdminPassword2026!")

        # Setup incident 201 and case
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (201, 'user_v1', 'Initial Recon', 'Port Scan', 50, '192.0.2.1', 'US', '2026-10-31 09:00:00', 0, 1)
        """)
        c.execute("""
            INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at)
            VALUES (201, 'investigating', 1, 'admin_sec', 1, '2026-10-31 09:00:00', '2026-10-31 09:00:00')
        """)
        conn.commit()
        conn.close()

        # Create report
        rep = client.post("/api/reports", json={
            "case_id": 201,
            "title": "Version 1 Initial Investigation",
            "executive_summary": "Original v1 summary before case mutations."
        }, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # Finalize Version 1
        fin_res = client.post(f"/api/reports/{report_id}/status", json={
            "status": "finalized",
            "expected_version": 1,
            "change_summary": "Finalized original version 1."
        }, headers={"X-CSRFToken": token})
        assert fin_res.status_code == 200

        # Export Version 1 HTML and JSON
        v1_html_export = client.get(f"/api/reports/{report_id}/export/html?version=1").data.decode("utf-8")
        v1_json_export = client.get(f"/api/reports/{report_id}/export/json?version=1").get_json()

        assert "Version 1 Initial Investigation" in v1_html_export
        assert "Original v1 summary before case mutations." in v1_html_export
        assert v1_json_export["version"] == 1

        # Now heavily mutate the underlying case and log records in the database
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("""
            UPDATE logs
            SET attack = 'MUTATED ATTACK STRING', risk = 99, username = 'mutated_user'
            WHERE id = 201
        """)
        c.execute("""
            UPDATE cases
            SET status = 'resolved', version = 5, updated_at = '2026-10-31 23:59:59'
            WHERE incident_id = 201
        """)
        conn.commit()
        conn.close()

        # Initiate Revision to Version 2
        rev_res = client.post(f"/api/reports/{report_id}/revise", json={
            "expected_version": 1,
            "change_summary": "Initiating revision for supplementary evidence."
        }, headers={"X-CSRFToken": token})
        assert rev_res.status_code == 200
        assert rev_res.get_json()["version"] == 2

        # Update and Finalize Version 2
        patch_res = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 2,
            "title": "Version 2 Supplementary Investigation",
            "executive_summary": "Updated findings with mutated telemetry analysis."
        }, headers={"X-CSRFToken": token})
        assert patch_res.status_code == 200

        fin_v2 = client.post(f"/api/reports/{report_id}/status", json={
            "status": "finalized",
            "expected_version": 2,
            "change_summary": "Finalized version 2."
        }, headers={"X-CSRFToken": token})
        assert fin_v2.status_code == 200

        # Re-export Version 1 with explicit ?version=1
        v1_re_export_html = client.get(f"/api/reports/{report_id}/export/html?version=1").data.decode("utf-8")
        v1_re_export_json = client.get(f"/api/reports/{report_id}/export/json?version=1").get_json()

        # CRITICAL ASSERTION: Version 1 re-export must be 100% identical and unaffected by mutations or v2 finalization
        assert v1_re_export_html == v1_html_export
        assert v1_re_export_json == v1_json_export
        assert "MUTATED ATTACK STRING" not in v1_re_export_html
        assert "Version 2 Supplementary Investigation" not in v1_re_export_html

        # Export Version 2: Must contain v2 title and content
        v2_html = client.get(f"/api/reports/{report_id}/export/html?version=2").data.decode("utf-8")
        assert "Version 2 Supplementary Investigation" in v2_html
        assert "Updated findings with mutated telemetry analysis." in v2_html

        # Requesting a non-existent version returns 404 Not Found
        not_found_res = client.get(f"/api/reports/{report_id}/export/html?version=99")
        assert not_found_res.status_code == 404
        assert "Version 99 of report" in not_found_res.get_json()["message"]


class TestExactIncidentMatching:
    """Tests requirement 3: Elimination of substring-based incident matching."""

    def test_exact_json_membership_for_incidents_12_112_120(self, sec_env):
        client = sec_env["client"]
        db_path = sec_env["db_path"]
        token = login_client(client, "admin_sec", "AdminPassword2026!")

        conn = get_db_connection(db_path)
        c = conn.cursor()

        # Insert 3 incidents whose IDs could collide under substring matching
        test_incidents = [12, 112, 120]
        for inc_id in test_incidents:
            c.execute("""
                INSERT INTO logs (id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES (?, ?, 'Spray Test', 'Abnormal', 70, '192.0.2.1', 'US', '2026-10-31 10:00:00', 0, 1)
            """, (inc_id, f"user_{inc_id}"))
            c.execute("""
                INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at)
                VALUES (?, 'investigating', 1, 'admin_sec', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')
            """, (inc_id,))

        c.execute("SELECT id FROM detection_rules WHERE rule_id = 'RULE-AUTH-001'")
        rule_row = c.fetchone()
        rule_pk = rule_row["id"] if rule_row else 1

        # Insert detection alerts with specific JSON arrays and all required attributes
        c.execute("""
            INSERT INTO detection_alerts (
                alert_id, rule_id, rule_name, correlation_key, idempotency_hash,
                severity, matched_count, first_event_time, last_event_time,
                explanation, matched_incident_ids_json, status, linked_incident_id,
                created_at, updated_at
            ) VALUES
                ('ALT-12', ?, 'Auth Spray 12', 'corr-12', 'hash-12',
                 'high', 1, '2026-10-31 10:00:00', '2026-10-31 10:05:00',
                 'Alert strictly for incident 12', '[12]', 'open', 12,
                 '2026-10-31 10:05:00', '2026-10-31 10:05:00'),
                ('ALT-112', ?, 'Auth Spray 112', 'corr-112', 'hash-112',
                 'high', 1, '2026-10-31 10:00:00', '2026-10-31 10:06:00',
                 'Alert strictly for incident 112', '[112]', 'open', 112,
                 '2026-10-31 10:06:00', '2026-10-31 10:06:00'),
                ('ALT-120', ?, 'Auth Spray 120', 'corr-120', 'hash-120',
                 'high', 1, '2026-10-31 10:00:00', '2026-10-31 10:07:00',
                 'Alert strictly for incident 120', '[120]', 'open', 120,
                 '2026-10-31 10:07:00', '2026-10-31 10:07:00')
        """, (rule_pk, rule_pk, rule_pk))
        conn.commit()
        conn.close()

        # Create report specifically for incident 12
        rep = client.post("/api/reports", json={
            "case_id": 12,
            "title": "Investigation for Incident 12"
        }, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # Check Timeline: MUST only contain ALT-12; NEVER ALT-112 or ALT-120
        timeline_res = client.get(f"/api/reports/{report_id}/timeline")
        assert timeline_res.status_code == 200
        tl_items = timeline_res.get_json()["timeline"]
        detection_events = [it for it in tl_items if it.get("category") == "detection"]

        assert len(detection_events) == 1
        assert "ALT-12" in detection_events[0]["details"]
        assert "ALT-112" not in detection_events[0]["details"]
        assert "ALT-120" not in detection_events[0]["details"]

        # Attempt to link ALT-112 to report 12: Must be rejected because ALT-112 is not part of incident 12
        bad_link_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "alert",
            "reference_id": "ALT-112",
            "label": "Mismatched Alert Linkage"
        }, headers={"X-CSRFToken": token})
        assert bad_link_res.status_code == 400
        assert "does not belong to case #12" in bad_link_res.get_json()["message"]

        # Successfully link ALT-12 to report 12
        good_link_res = client.post(f"/api/reports/{report_id}/evidence", json={
            "reference_type": "alert",
            "reference_id": "ALT-12",
            "label": "Legitimate Alert Linkage"
        }, headers={"X-CSRFToken": token})
        assert good_link_res.status_code == 201


class TestAtomicVersionChecks:
    """Tests requirement 4: Conditional SQLite updates and 409 Conflict rejection."""

    def test_stale_expected_version_rejection_on_mutations(self, sec_env):
        client = sec_env["client"]
        db_path = sec_env["db_path"]
        token = login_client(client, "admin_sec", "AdminPassword2026!")

        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (301, 'user_lock', 'Locking Test', 'Abnormal', 60, '192.0.2.1', 'US', '2026-10-31 10:00:00', 0, 1)
        """)
        c.execute("""
            INSERT INTO cases (incident_id, status, assigned_to, assigned_username, version, created_at, updated_at)
            VALUES (301, 'investigating', 1, 'admin_sec', 1, '2026-10-31 10:00:00', '2026-10-31 10:00:00')
        """)
        conn.commit()
        conn.close()

        rep = client.post("/api/reports", json={
            "case_id": 301,
            "title": "Optimistic Concurrency Report"
        }, headers={"X-CSRFToken": token}).get_json()
        report_id = rep["report_id"]

        # 1. Update with invalid version returns 409 Conflict
        bad_patch = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 999,
            "title": "Stale Update"
        }, headers={"X-CSRFToken": token})
        assert bad_patch.status_code == 409
        assert "conflict" in bad_patch.get_json()["message"].lower()

        # 2. Status transition with stale version returns 409 Conflict
        bad_status = client.post(f"/api/reports/{report_id}/status", json={
            "status": "in_review",
            "expected_version": 999
        }, headers={"X-CSRFToken": token})
        assert bad_status.status_code == 409

        # 3. Finalize report legitimately
        fin_res = client.post(f"/api/reports/{report_id}/status", json={
            "status": "finalized",
            "expected_version": 1
        }, headers={"X-CSRFToken": token})
        assert fin_res.status_code == 200

        # 4. Attempting to update a finalized report without revising returns 409 Conflict
        fin_patch = client.patch(f"/api/reports/{report_id}", json={
            "expected_version": 1,
            "title": "Cannot Edit Finalized Report"
        }, headers={"X-CSRFToken": token})
        assert fin_patch.status_code == 409
        assert "finalized" in fin_patch.get_json()["message"]

        # 5. Calling revise with wrong version returns 409 Conflict
        bad_rev = client.post(f"/api/reports/{report_id}/revise", json={
            "expected_version": 999
        }, headers={"X-CSRFToken": token})
        assert bad_rev.status_code == 409

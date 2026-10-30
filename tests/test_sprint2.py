"""
AuthGuard-X Sprint 2 — Investigation & Case Management Test Suite
Comprehensive coverage for:
  - Additive database schema and idempotent migrations
  - Incident investigation lifecycle state machine (new -> investigating -> contained -> resolved)
  - Controlled case reopening
  - Mandatory resolution documentation
  - Analyst assignment, self-claiming, and RBAC restrictions
  - Persistent investigation notes with server-derived author attribution
  - Evidence metadata references and dangerous URL scheme validation
  - Append-only activity audit trail
  - Administrative log purge protection policy
  - Analyst work queue and unassigned case filtering
  - SOC investigation analytics and metrics calculation
  - Legacy endpoint synchronization (logs.resolved <-> cases.status)
  - CSRF enforcement on case mutation endpoints
  - User provisioning (admin-only) with bcrypt hashing
"""
import os
import sys
import tempfile
import sqlite3
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, init_db, get_db_connection


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_env(tmp_path):
    """Isolated database and test client with CSRF disabled for unit tests."""
    db_file = tmp_path / "test_sprint2.db"
    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "SECRET_KEY": "sprint2-test-secret-key",
        "ENABLE_EXTERNAL_GEOIP": False,
    }
    app = create_app(test_config=config)
    with app.test_client() as client:
        yield client, config, str(db_file)


@pytest.fixture
def authed_admin(test_env):
    """Pre-authenticated administrator client."""
    client, config, db_path = test_env
    res = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "AdminPassword2026!"
    })
    assert res.status_code == 200
    return client, config, db_path


@pytest.fixture
def authed_analyst(test_env):
    """Pre-authenticated analyst client (analyst_john)."""
    client, config, db_path = test_env
    res = client.post("/api/auth/login", json={
        "username": "analyst_john",
        "password": "AnalystJohn2026!"
    })
    assert res.status_code == 200
    return client, config, db_path


def _create_incident(client, attack="SQL Injection Attempt", risk=85, username="victim_user"):
    res = client.post("/api/incidents/simulate", json={
        "attack": attack,
        "risk": risk,
        "behavior": "sqli_probe",
        "username": username
    })
    assert res.status_code == 201
    return res.get_json()["incident"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_init_db_idempotent_migration(tmp_path):
    """Verifies that init_db safely creates new tables and backfills cases idempotently."""
    db_file = tmp_path / "migration_test.db"
    db_path = str(db_file)

    # 1. Simulate legacy DB with logs table only
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, attack TEXT, behavior TEXT, risk INTEGER,
            ip TEXT, location TEXT, time TEXT, resolved INTEGER DEFAULT 0, is_simulated INTEGER DEFAULT 0
        )
    """)
    conn.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 ("user1", "Brute Force", "auth_flood", 70, "127.0.0.1", "Local", "2026-10-30 10:00:00", 0))
    conn.execute("INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 ("user2", "Password Spray", "spray", 60, "127.0.0.1", "Local", "2026-10-30 11:00:00", 1))
    conn.commit()
    conn.close()

    # 2. Run Sprint 2 init_db
    init_db(db_path, "development", True, True, "admin", "Admin2026!")

    # Verify tables created
    conn = get_db_connection(db_path)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "cases" in tables
    assert "incident_notes" in tables
    assert "incident_evidence" in tables
    assert "incident_audit_log" in tables

    # Verify backfill: log 1 -> 'new', log 2 -> 'resolved'
    cases = conn.execute("SELECT incident_id, status FROM cases ORDER BY incident_id ASC").fetchall()
    assert len(cases) == 2
    assert cases[0]["incident_id"] == 1
    assert cases[0]["status"] == "new"
    assert cases[1]["incident_id"] == 2
    assert cases[1]["status"] == "resolved"

    # 3. Run init_db again to verify idempotency (must not error or duplicate)
    init_db(db_path, "development", True, True, "admin", "Admin2026!")
    cases_after = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    assert cases_after == 2
    conn.close()


def test_simulation_creates_case_and_audit(authed_admin):
    """Simulating an attack must transactionally create a case and audit log entry."""
    client, _, db_path = authed_admin
    inc = _create_incident(client, attack="Credential Stuffing", risk=82)
    inc_id = inc["id"]

    # Verify case endpoint returns case data
    res = client.get(f"/api/incidents/{inc_id}/case")
    assert res.status_code == 200
    data = res.get_json()

    assert data["incident"]["id"] == inc_id
    assert data["case"]["status"] == "new"
    assert data["case"]["assigned_to"] is None

    # Verify audit trail contains creation event
    activity = data["activity"]
    assert len(activity) >= 1
    assert activity[0]["action"] == "incident_created"
    assert activity[0]["after_value"] == "new"


def test_valid_lifecycle_state_machine(authed_admin):
    """Tests progression: new -> investigating -> contained -> resolved."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Ransomware Dropper", risk=95)
    inc_id = inc["id"]

    # 1. new -> investigating
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})
    assert res.status_code == 200
    case_data = res.get_json()["case"]
    assert case_data["status"] == "investigating"
    assert case_data["investigation_started_at"] is not None

    # Check logs table resolved flag is still 0
    inc_res = client.get(f"/api/incidents/{inc_id}")
    assert inc_res.get_json()["resolved"] == 0

    # 2. investigating -> contained
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "contained"})
    assert res.status_code == 200
    case_data = res.get_json()["case"]
    assert case_data["status"] == "contained"
    assert case_data["contained_at"] is not None

    # Check logs table resolved flag is still 0
    inc_res = client.get(f"/api/incidents/{inc_id}")
    assert inc_res.get_json()["resolved"] == 0

    # 3. contained -> resolved (with resolution summary)
    res = client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "resolved",
        "resolution_summary": "Malicious payload quarantined, endpoint disconnected and reimaged."
    })
    assert res.status_code == 200
    case_data = res.get_json()["case"]
    assert case_data["status"] == "resolved"
    assert case_data["resolved_at"] is not None
    assert "quarantined" in case_data["resolution_summary"]

    # Check logs table resolved flag synchronized to 1
    inc_res = client.get(f"/api/incidents/{inc_id}")
    assert inc_res.get_json()["resolved"] == 1


def test_invalid_lifecycle_transitions_rejected(authed_admin):
    """Enforces strict state machine transition validation."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="API Flooding", risk=65)
    inc_id = inc["id"]

    # 1. Cannot skip directly from new to resolved
    res = client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "resolved",
        "resolution_summary": "Skipping investigation without triage"
    })
    assert res.status_code == 400
    assert "Invalid status transition" in res.get_json()["message"]

    # 2. Cannot skip directly from new to contained
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "contained"})
    assert res.status_code == 400

    # Transition to investigating
    client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})

    # 3. Cannot transition from investigating back to new
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "new"})
    assert res.status_code == 400

    # Resolve the case
    client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "resolved",
        "resolution_summary": "Triage complete, verified resolved"
    })

    # 4. Cannot transition from resolved to new or contained
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "new"})
    assert res.status_code == 400
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "contained"})
    assert res.status_code == 400


def test_reopen_workflow(authed_admin):
    """Reopening a resolved case transitions it to investigating and clears resolved flag."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Beaconing Anomaly", risk=78)
    inc_id = inc["id"]

    # Move to investigating then resolved
    client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})
    client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "resolved",
        "resolution_summary": "Initial remediation applied"
    })

    # Attempt reopen without reason
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})
    assert res.status_code == 400
    assert "reopen reason" in res.get_json()["message"].lower()

    # Reopen with valid reason
    res = client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "investigating",
        "reopen_reason": "Secondary C2 beacon detected on adjacent subnet, reopening investigation."
    })
    assert res.status_code == 200
    case_data = res.get_json()["case"]
    assert case_data["status"] == "investigating"
    assert case_data["resolved_at"] is None

    # Check logs table resolved flag reset to 0
    inc_res = client.get(f"/api/incidents/{inc_id}")
    assert inc_res.get_json()["resolved"] == 0

    # Check audit log records reopen
    audit_res = client.get(f"/api/incidents/{inc_id}/activity")
    actions = [a["action"] for a in audit_res.get_json()]
    assert "incident_reopened" in actions


def test_resolution_requires_meaningful_summary(authed_admin):
    """Resolving an incident requires a resolution summary >= 5 chars."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Phishing Link Click", risk=55)
    inc_id = inc["id"]

    client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})

    # Empty summary
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "resolved", "resolution_summary": ""})
    assert res.status_code == 400

    # Too short summary (< 5 chars)
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "resolved", "resolution_summary": "done"})
    assert res.status_code == 400

    # Valid summary
    res = client.patch(f"/api/incidents/{inc_id}/case", json={
        "status": "resolved",
        "resolution_summary": "User password reset, mailbox rules audited, no mail exfiltrated."
    })
    assert res.status_code == 200


def test_case_assignment_admin(authed_admin):
    """Administrator can assign, reassign, and unassign cases."""
    client, _, db_path = authed_admin
    inc = _create_incident(client, attack="Port Scan", risk=40)
    inc_id = inc["id"]

    # Assign to analyst_john
    res = client.post(f"/api/incidents/{inc_id}/assign", json={"username": "analyst_john"})
    assert res.status_code == 200
    assert res.get_json()["assigned_username"] == "analyst_john"

    # Reassign to analyst_jane
    res = client.post(f"/api/incidents/{inc_id}/assign", json={"username": "analyst_jane"})
    assert res.status_code == 200
    assert res.get_json()["assigned_username"] == "analyst_jane"

    # Unassign
    res = client.post(f"/api/incidents/{inc_id}/assign", json={"unassign": True})
    assert res.status_code == 200
    assert res.get_json()["assigned_to"] is None


def test_case_assignment_analyst_claim(test_env):
    """Analyst can claim unassigned case, but cannot claim someone else's case or assign to other users."""
    client, _, _ = test_env

    # 1. Admin creates incident
    client.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})
    inc = _create_incident(client, attack="Suspicious DLL Load", risk=72)
    inc_id = inc["id"]
    client.post("/api/auth/logout")

    # 2. Log in as analyst_john
    client.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})
    john_id = client.get("/api/auth/session").get_json()["user"]["id"]

    # Analyst claiming for himself succeeds
    res = client.post(f"/api/incidents/{inc_id}/assign", json={"assigned_to": john_id})
    assert res.status_code == 200
    assert res.get_json()["assigned_username"] == "analyst_john"

    # Analyst trying to assign to another user fails (403)
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "analyst_jane", "password": "AnalystJane2026!"})
    jane_id = client.get("/api/auth/session").get_json()["user"]["id"]

    res = client.post(f"/api/incidents/{inc_id}/assign", json={"assigned_to": jane_id})
    assert res.status_code == 403


def test_analyst_rbac_status_transition(test_env):
    """An analyst cannot modify status of a case assigned to another analyst."""
    client, _, _ = test_env

    # Admin creates and assigns case to analyst_john
    client.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})
    inc = _create_incident(client, attack="Pass the Hash", risk=88)
    inc_id = inc["id"]
    client.post(f"/api/incidents/{inc_id}/assign", json={"username": "analyst_john"})
    client.post("/api/auth/logout")

    # Log in as analyst_jane and attempt status modification
    client.post("/api/auth/login", json={"username": "analyst_jane", "password": "AnalystJane2026!"})
    res = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})
    assert res.status_code == 403
    assert "assigned to another analyst" in res.get_json()["message"]


def test_case_notes_creation_and_persistence(authed_analyst):
    """Case notes must be persisted with session-derived author identity."""
    client, _, _ = authed_analyst
    inc = _create_incident(client, attack="Kerberoasting", risk=79)
    inc_id = inc["id"]

    # Post note
    res = client.post(f"/api/incidents/{inc_id}/notes", json={
        "content": "Observed unusual SPN requests for domain service accounts."
    })
    assert res.status_code == 201
    note = res.get_json()["note"]
    assert note["author_username"] == "analyst_john"
    assert "SPN requests" in note["content"]

    # Fetch notes
    res = client.get(f"/api/incidents/{inc_id}/notes")
    assert res.status_code == 200
    notes = res.get_json()
    assert len(notes) == 1
    assert notes[0]["author_username"] == "analyst_john"

    # Empty note rejected
    res = client.post(f"/api/incidents/{inc_id}/notes", json={"content": "   "})
    assert res.status_code == 400


def test_case_notes_xss_safety(authed_admin):
    """Notes with script tags are stored safely without injection."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Cross-Site Scripting Probe", risk=60)
    inc_id = inc["id"]

    xss_payload = "<script>alert('pwned')</script><b>bold observation</b>"
    res = client.post(f"/api/incidents/{inc_id}/notes", json={"content": xss_payload})
    assert res.status_code == 201

    res = client.get(f"/api/incidents/{inc_id}/notes")
    notes = res.get_json()
    assert notes[0]["content"] == xss_payload


def test_case_evidence_metadata_validation(authed_admin):
    """Evidence metadata is validated, rejecting empty titles and dangerous URL schemes."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Data Staging", risk=84)
    inc_id = inc["id"]

    # 1. Missing title
    res = client.post(f"/api/incidents/{inc_id}/evidence", json={
        "title": "",
        "evidence_type": "log_excerpt",
        "source_ref": "https://siem.internal/logs/1"
    })
    assert res.status_code == 400

    # 2. Dangerous URL scheme (javascript:)
    res = client.post(f"/api/incidents/{inc_id}/evidence", json={
        "title": "Malicious payload ref",
        "evidence_type": "external_report",
        "source_ref": "javascript:alert(1)"
    })
    assert res.status_code == 400
    assert "unsafe" in res.get_json()["message"].lower()

    # 3. Valid evidence metadata reference
    res = client.post(f"/api/incidents/{inc_id}/evidence", json={
        "title": "Staged Archive File Hash",
        "evidence_type": "hash_indicator",
        "source_ref": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "description": "SHA-256 hash of suspicious archive identified in C:\\Temp."
    })
    assert res.status_code == 201
    ev = res.get_json()["evidence"]
    assert ev["evidence_type"] == "hash_indicator"
    assert ev["added_by_username"] == "testadmin"

    # Fetch evidence
    res = client.get(f"/api/incidents/{inc_id}/evidence")
    assert len(res.get_json()) == 1


def test_clear_logs_protection_policy(authed_admin):
    """Administrator cannot silently purge logs when active notes/evidence exist without force_purge."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Active Directory Recon", risk=62)
    inc_id = inc["id"]

    # Add evidence to make it an active investigation
    client.post(f"/api/incidents/{inc_id}/notes", json={"content": "Important triage notes."})

    # Standard clear attempt should fail with 400 and explanation
    res = client.post("/api/incidents/clear", json={})
    assert res.status_code == 400
    assert "force_purge_investigations" in res.get_json()["error"]

    # Force purge succeeds
    res = client.post("/api/incidents/clear", json={"force_purge_investigations": True})
    assert res.status_code == 200
    assert res.get_json()["status"] == "success"

    # Verify tables wiped
    res = client.get("/api/incidents")
    assert len(res.get_json()) == 0


def test_my_queue_filtering(test_env):
    """Work queue endpoint returns only cases assigned to the authenticated user."""
    client, _, _ = test_env

    # Admin logs in, creates 2 incidents, assigns 1 to john, 1 to jane
    client.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})
    inc1 = _create_incident(client, attack="Attack for John", risk=70)
    inc2 = _create_incident(client, attack="Attack for Jane", risk=60)
    client.post(f"/api/incidents/{inc1['id']}/assign", json={"username": "analyst_john"})
    client.post(f"/api/incidents/{inc2['id']}/assign", json={"username": "analyst_jane"})
    client.post("/api/auth/logout")

    # Log in as analyst_john
    client.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})
    res = client.get("/api/cases/my-queue")
    assert res.status_code == 200
    cases = res.get_json()
    assert len(cases) == 1
    assert cases[0]["attack"] == "Attack for John"


def test_unassigned_cases_endpoint(authed_admin):
    """Returns only open cases that have not yet been assigned to an analyst."""
    client, _, _ = authed_admin
    inc1 = _create_incident(client, attack="Unassigned 1", risk=60)
    inc2 = _create_incident(client, attack="Assigned 2", risk=70)
    client.post(f"/api/incidents/{inc2['id']}/assign", json={"username": "analyst_john"})

    res = client.get("/api/cases/unassigned")
    assert res.status_code == 200
    cases = res.get_json()
    assert any(c["id"] == inc1["id"] for c in cases)
    assert not any(c["id"] == inc2["id"] for c in cases)


def test_investigation_metrics_calculation(authed_admin):
    """Aggregates accurate counts for new, investigating, contained, resolved, and avg duration."""
    client, _, _ = authed_admin

    # Create 3 incidents: 1 new, 1 investigating, 1 resolved
    inc_new = _create_incident(client, attack="New Vector", risk=50)
    inc_inv = _create_incident(client, attack="Inv Vector", risk=60)
    inc_res = _create_incident(client, attack="Res Vector", risk=85)

    client.patch(f"/api/incidents/{inc_inv['id']}/case", json={"status": "investigating"})

    client.patch(f"/api/incidents/{inc_res['id']}/case", json={"status": "investigating"})
    client.patch(f"/api/incidents/{inc_res['id']}/case", json={
        "status": "resolved",
        "resolution_summary": "Resolved successfully"
    })

    res = client.get("/api/metrics/investigations")
    assert res.status_code == 200
    m = res.get_json()

    assert m["new"] >= 1
    assert m["investigating"] >= 1
    assert m["resolved"] >= 1
    assert "avg_resolution_human" in m


def test_legacy_resolve_syncs_case(authed_admin):
    """Calling legacy POST /api/incidents/<id>/resolve updates both logs and cases."""
    client, _, _ = authed_admin
    inc = _create_incident(client, attack="Legacy Route Test", risk=77)
    inc_id = inc["id"]

    res = client.post(f"/api/incidents/{inc_id}/resolve")
    assert res.status_code == 200

    # Verify both logs and case state
    case_res = client.get(f"/api/incidents/{inc_id}/case")
    case_data = case_res.get_json()["case"]
    assert case_data["status"] == "resolved"
    assert case_data["resolved_at"] is not None

    inc_res = client.get(f"/api/incidents/{inc_id}")
    assert inc_res.get_json()["resolved"] == 1


def test_csrf_enforcement_on_case_endpoints(tmp_path):
    """Mutating case endpoints reject requests when CSRF token is missing with WTF_CSRF_ENABLED=True."""
    db_file = tmp_path / "csrf_case_test.db"
    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "admin",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "SECRET_KEY": "csrf-secret-key",
    }
    app = create_app(test_config=config)
    with app.test_client() as client:
        # 1. Fetch token and login
        token_res = client.get("/api/auth/csrf-token")
        token = token_res.get_json()["csrf_token"]

        login_res = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "AdminPassword2026!"
        }, headers={"X-CSRFToken": token})
        assert login_res.status_code == 200

        # Refresh token after session establishment
        token = client.get("/api/auth/csrf-token").get_json()["csrf_token"]

        # 2. Simulate incident with CSRF
        sim_res = client.post("/api/incidents/simulate", json={
            "attack": "CSRF Test",
            "risk": 70
        }, headers={"X-CSRFToken": token})
        assert sim_res.status_code == 201
        inc_id = sim_res.get_json()["incident"]["id"]

        # 3. Missing CSRF on PATCH /case should be rejected (400)
        res_no_csrf = client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating"})
        assert res_no_csrf.status_code == 400

        # 4. Valid CSRF on PATCH /case accepted (200)
        token = client.get("/api/auth/csrf-token").get_json()["csrf_token"]
        res_with_csrf = client.patch(f"/api/incidents/{inc_id}/case", json={
            "status": "investigating"
        }, headers={"X-CSRFToken": token})
        assert res_with_csrf.status_code == 200


def test_user_provisioning_admin_only(authed_admin, test_env):
    """Only administrators can provision new users via POST /api/users/create."""
    client, _, db_path = authed_admin

    # Admin creates new analyst
    res = client.post("/api/users/create", json={
        "username": "analyst_sarah",
        "password": "SarahPassword2026!",
        "role": "analyst"
    })
    assert res.status_code == 201
    assert res.get_json()["user"]["username"] == "analyst_sarah"

    # Verify password in DB is hashed with bcrypt
    conn = get_db_connection(db_path)
    pw_hash = conn.execute("SELECT password FROM users WHERE username = 'analyst_sarah'").fetchone()["password"]
    assert pw_hash.startswith(b"$2b$") or pw_hash.startswith(b"$2a$")
    conn.close()

    # Non-admin attempting user creation fails (403)
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})
    res = client.post("/api/users/create", json={
        "username": "analyst_hacker",
        "password": "Password123!",
        "role": "admin"
    })
    assert res.status_code == 403


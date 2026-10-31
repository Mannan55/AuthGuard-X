"""
AuthGuard-X Sprint 4 Test Suite — Security Event Ingestion & Realistic SOC Lab

Tests:
1. Multi-format parser engine (Canonical CSV, NDJSON, Windows 4624/4625, Linux SSH, Zeek conn.log)
2. Normalized event schema and database persistence
3. Deterministic deduplication via SHA-256 fingerprint
4. Batch tracking and error summary reporting
5. Input limits: 5MB file cap, 5,000 records cap, IP validation, path traversal defense
6. CSV formula injection defense
7. Detection pipeline correlation with deterministic event timestamps
8. Event Explorer pagination, filtering, search, and details
9. Pre-packaged realistic SOC training datasets loading
10. Authentication and CSRF protection on ingestion endpoints
"""

import io
import json
import sqlite3
import pytest
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, init_db
from ingestion import IngestionParser, sanitize_csv_formula, calculate_fingerprint, normalize_timestamp


@pytest.fixture
def test_env(tmp_path):
    db_file = tmp_path / "test_sprint4.db"
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": "sprint4-test-secret-key-very-secure",
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


# ==============================================================================
# 1. PARSER ENGINE UNIT TESTS
# ==============================================================================

def test_parser_canonical_csv():
    csv_data = """timestamp,source_ip,dest_ip,attack,category,username,hostname,outcome,risk,behavior
2026-10-31 10:00:00,198.51.100.10,10.0.0.1,Credential Stuffing,Authentication,alice,web-srv,failure,85,Failed login attempt
2026-10-31 10:00:05,198.51.100.10,10.0.0.1,Credential Stuffing,Authentication,bob,web-srv,failure,85,Failed login attempt
"""
    records, errors, fmt = IngestionParser.parse_content(csv_data, format_name="canonical_csv")
    assert fmt == "canonical_csv"
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["username"] == "alice"
    assert records[0]["source_ip"] == "198.51.100.10"
    assert records[0]["outcome"] == "failure"
    assert records[0]["severity"] == "critical"
    assert records[0]["risk_score"] == 85


def test_parser_ndjson():
    ndjson_data = """{"time": "2026-10-31 10:10:00", "source_ip": "203.0.113.5", "attack": "Brute Force", "username": "admin", "outcome": "failure", "risk": 75}
{"time": "2026-10-31 10:10:05", "source_ip": "203.0.113.5", "attack": "Brute Force", "username": "root", "outcome": "failure", "risk": 75}
"""
    records, errors, fmt = IngestionParser.parse_content(ndjson_data, format_name="ndjson")
    assert fmt == "ndjson"
    assert len(errors) == 0
    assert len(records) == 2
    assert records[1]["username"] == "root"
    assert records[1]["source_ip"] == "203.0.113.5"


def test_parser_windows_security_event_json():
    windows_data = json.dumps([
        {
            "Event": {
                "System": {
                    "EventID": 4625,
                    "TimeCreated": {"@SystemTime": "2026-10-31T11:00:00.000Z"},
                    "Computer": "DC01.corp.internal"
                },
                "EventData": {
                    "TargetUserName": "svc_sql",
                    "IpAddress": "192.168.1.150",
                    "LogonType": "3",
                    "SubStatus": "0xC000006A"
                }
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"@SystemTime": "2026-10-31T11:01:00.000Z"},
                    "Computer": "DC01.corp.internal"
                },
                "EventData": {
                    "TargetUserName": "analyst1",
                    "IpAddress": "10.0.0.88",
                    "LogonType": "2"
                }
            }
        }
    ])
    records, errors, fmt = IngestionParser.parse_content(windows_data, format_name="windows_event")
    assert fmt == "windows_event"
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["outcome"] == "failure"
    assert records[0]["attack_type"] == "Logon Failure (Windows 4625)"
    assert records[0]["username"] == "svc_sql"
    assert records[1]["outcome"] == "success"
    assert records[1]["attack_type"] == "Logon Success (Windows 4624)"


def test_parser_linux_ssh_auth_log():
    ssh_data = """Oct 31 12:00:01 bastion sshd[1001]: Failed password for root from 198.51.100.77 port 54110 ssh2
Oct 31 12:00:03 bastion sshd[1002]: Failed password for invalid user admin from 198.51.100.77 port 54112 ssh2
Oct 31 12:00:10 bastion sshd[1005]: Accepted publickey for secops from 192.168.1.50 port 54114 ssh2
"""
    records, errors, fmt = IngestionParser.parse_content(ssh_data, format_name="linux_ssh")
    assert fmt == "linux_ssh"
    assert len(errors) == 0
    assert len(records) == 3
    assert records[0]["username"] == "root"
    assert records[0]["outcome"] == "failure"
    assert records[1]["username"] == "admin"
    assert records[1]["outcome"] == "failure"
    assert records[2]["username"] == "secops"
    assert records[2]["outcome"] == "success"


def test_parser_zeek_conn_log():
    zeek_data = json.dumps([
        {"ts": 1793440000.0, "id.orig_h": "203.0.113.88", "id.resp_h": "10.0.0.5", "id.resp_p": 22, "proto": "tcp", "conn_state": "S0"},
        {"ts": 1793440001.0, "id.orig_h": "203.0.113.88", "id.resp_h": "10.0.0.5", "id.resp_p": 80, "proto": "tcp", "conn_state": "S0"},
        {"ts": 1793440005.0, "id.orig_h": "10.0.0.99", "id.resp_h": "10.0.0.5", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}
    ])
    records, errors, fmt = IngestionParser.parse_content(zeek_data, format_name="zeek_conn")
    assert fmt == "zeek_conn"
    assert len(errors) == 0
    assert len(records) == 3
    assert records[0]["outcome"] == "blocked"
    assert "S0" in records[0]["attack_type"]
    assert records[2]["outcome"] == "success"


def test_formula_injection_sanitization():
    assert sanitize_csv_formula("=1+1") == "'=1+1"
    assert sanitize_csv_formula("+CMD") == "'+CMD"
    assert sanitize_csv_formula("-EXEC") == "'-EXEC"
    assert sanitize_csv_formula("@SUM(A1:A5)") == "'@SUM(A1:A5)"
    assert sanitize_csv_formula("\tTabbed") == "'\tTabbed"
    assert sanitize_csv_formula("Normal Text") == "Normal Text"
    assert sanitize_csv_formula(12345) == "12345"


# ==============================================================================
# 2. INGESTION API & DEDUPLICATION INTEGRATION TESTS
# ==============================================================================

def test_import_security_logs_endpoint_success_and_deduplication(test_env):
    client = test_env["client"]
    token = login_user(client)

    csv_payload = """timestamp,source_ip,dest_ip,attack,category,username,hostname,outcome,risk,behavior
2026-10-31 14:00:01,198.51.100.200,10.0.0.1,Brute Force,Authentication,victim1,corp-dc,failure,85,Failed login
2026-10-31 14:00:03,198.51.100.200,10.0.0.1,Brute Force,Authentication,victim2,corp-dc,failure,85,Failed login
2026-10-31 14:00:05,198.51.100.200,10.0.0.1,Brute Force,Authentication,victim3,corp-dc,failure,85,Failed login
"""
    # 1. First Import
    res = client.post("/api/ingestion/import", json={
        "content": csv_payload,
        "format": "canonical_csv",
        "filename": "brute_force_test.csv"
    }, headers={"X-CSRFToken": token})

    assert res.status_code == 201
    data = res.get_json()
    assert data["status"] == "success"
    assert data["accepted_records"] == 3
    assert data["duplicate_records"] == 0
    batch_id = data["batch_id"]

    # Verify database persistence
    conn = get_db_connection(test_env["db_path"])
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS c FROM security_events WHERE batch_id = ?", (batch_id,))
    assert c.fetchone()["c"] == 3

    c.execute("SELECT COUNT(*) AS c FROM logs WHERE provenance = 'imported_unverified'")
    assert c.fetchone()["c"] == 3

    # Check that cases were generated for the imported telemetry
    c.execute("SELECT COUNT(*) AS c FROM cases")
    assert c.fetchone()["c"] >= 3
    conn.close()

    # 2. Second Import with identical payload (Deduplication Check)
    res_dup = client.post("/api/ingestion/import", json={
        "content": csv_payload,
        "format": "canonical_csv",
        "filename": "brute_force_test.csv"
    }, headers={"X-CSRFToken": token})

    assert res_dup.status_code == 201
    dup_data = res_dup.get_json()
    assert dup_data["accepted_records"] == 0
    assert dup_data["duplicate_records"] == 3

    # Total events stored remains 3
    conn2 = get_db_connection(test_env["db_path"])
    c2 = conn2.cursor()
    c2.execute("SELECT COUNT(*) AS c FROM security_events")
    assert c2.fetchone()["c"] == 3
    conn2.close()


def test_import_untrusted_input_validation_and_size_limits(test_env):
    client = test_env["client"]
    token = login_user(client)

    # Empty content rejected
    res_empty = client.post("/api/ingestion/import", json={
        "content": "   ",
        "format": "canonical_csv"
    }, headers={"X-CSRFToken": token})
    assert res_empty.status_code == 400

    # Malformed data with bad IPs recorded in rejected_records
    bad_csv = """timestamp,source_ip,attack,outcome
2026-10-31 10:00:00,not-an-ip,Bad IP Attack,failure
2026-10-31 10:00:01,999.999.999.999,Invalid Range Attack,failure
"""
    res_bad = client.post("/api/ingestion/import", json={
        "content": bad_csv,
        "format": "canonical_csv"
    }, headers={"X-CSRFToken": token})
    assert res_bad.status_code == 400
    assert "Invalid or missing source IP address" in res_bad.get_json()["errors"][0]["error"]


def test_ingestion_batches_and_event_explorer_endpoints(test_env):
    client = test_env["client"]
    token = login_user(client)

    # Import sample data
    csv_payload = """timestamp,source_ip,dest_ip,attack,category,username,hostname,outcome,risk
2026-10-31 15:00:00,192.168.1.100,10.0.0.2,SQL Injection,Web Attack,attacker,web01,blocked,90
2026-10-31 15:05:00,192.168.1.101,10.0.0.2,Valid Login,Authentication,admin,web01,success,10
"""
    res_import = client.post("/api/ingestion/import", json={
        "content": csv_payload,
        "format": "canonical_csv",
        "filename": "explorer_test.csv"
    }, headers={"X-CSRFToken": token})
    assert res_import.status_code == 201
    batch_id = res_import.get_json()["batch_id"]

    # 1. Batches feed
    res_batches = client.get("/api/ingestion/batches")
    assert res_batches.status_code == 200
    b_data = res_batches.get_json()
    assert b_data["total"] >= 1
    assert any(b["batch_id"] == batch_id for b in b_data["batches"])

    # 2. Single batch detail
    res_b_detail = client.get(f"/api/ingestion/batches/{batch_id}")
    assert res_b_detail.status_code == 200
    detail_data = res_b_detail.get_json()
    assert detail_data["batch_id"] == batch_id
    assert len(detail_data["sample_events"]) == 2

    # 3. Security Event Explorer with filters
    res_events = client.get("/api/ingestion/events?category=Web Attack")
    assert res_events.status_code == 200
    ev_data = res_events.get_json()
    assert ev_data["total"] == 1
    assert ev_data["events"][0]["category"] == "Web Attack"
    event_id = ev_data["events"][0]["id"]

    # 4. Single Security Event detail
    res_ev_detail = client.get(f"/api/ingestion/events/{event_id}")
    assert res_ev_detail.status_code == 200
    item = res_ev_detail.get_json()
    assert item["id"] == event_id
    assert item["category"] == "Web Attack"
    assert item["case"] is not None  # linked case present


def test_load_sample_datasets_endpoint(test_env):
    client = test_env["client"]
    token = login_user(client)

    # 1. List sample datasets
    res_list = client.get("/api/ingestion/samples")
    assert res_list.status_code == 200
    samples = res_list.get_json()["samples"]
    assert len(samples) >= 5
    sample_ids = [s["id"] for s in samples]
    assert "ssh_bursts" in sample_ids
    assert "windows_auth_failures" in sample_ids
    assert "zeek_recon_probes" in sample_ids
    assert "canonical_mixed" in sample_ids
    assert "benign_traffic" in sample_ids

    # 2. Load one sample dataset (e.g. windows_auth_failures)
    res_load = client.post("/api/ingestion/samples/load", json={
        "sample_id": "windows_auth_failures"
    }, headers={"X-CSRFToken": token})
    assert res_load.status_code == 201
    load_data = res_load.get_json()
    assert load_data["status"] == "success"
    assert load_data["accepted_records"] >= 3


def test_export_security_events_csv(test_env):
    client = test_env["client"]
    token = login_user(client)

    # Import an event with potential formula trigger
    csv_payload = """timestamp,source_ip,attack,username,outcome,risk
2026-10-31 16:00:00,10.0.0.1,=cmd|' /C calc'!A0,=calc_user,failure,75
"""
    client.post("/api/ingestion/import", json={
        "content": csv_payload,
        "format": "canonical_csv"
    }, headers={"X-CSRFToken": token})

    # Export to CSV
    res_export = client.get("/api/ingestion/export")
    assert res_export.status_code == 200
    assert "text/csv" in res_export.content_type
    content = res_export.data.decode("utf-8")

    # Formula injection values must be safely sanitized with leading single-quote
    assert "'=cmd|" in content or "'=calc_user" in content


def test_ingestion_requires_authentication_and_csrf(test_env):
    client = test_env["client"]

    # Unauthenticated GET calls blocked
    assert client.get("/api/ingestion/batches").status_code == 401
    assert client.get("/api/ingestion/events").status_code == 401

    # Unauthenticated POST with valid CSRF token rejected by @login_required with 401
    csrf_tok = get_csrf_token(client)
    res_unauth = client.post("/api/ingestion/import", json={"content": "test"}, headers={"X-CSRFToken": csrf_tok})
    assert res_unauth.status_code == 401

    # Missing CSRF token rejected with 400 even when logged in
    login_user(client)
    res_no_csrf = client.post("/api/ingestion/import", json={
        "content": "test",
        "format": "canonical_csv"
    })  # No X-CSRFToken header
    assert res_no_csrf.status_code == 400


def test_historical_import_triggers_correlated_detection_alerts(test_env):
    """Importing historical logs within sliding window triggers deterministic detection alerts."""
    client = test_env["client"]
    token = login_user(client)

    # 5 attempts within 40 seconds from same attacker IP targeting 5 distinct users
    spray_csv = """timestamp,source_ip,attack,category,username,outcome,risk
2026-10-31 04:00:01,198.51.100.99,SSH Login Attempt,Authentication,usr_alpha,failure,85
2026-10-31 04:00:05,198.51.100.99,SSH Login Attempt,Authentication,usr_beta,failure,85
2026-10-31 04:00:10,198.51.100.99,SSH Login Attempt,Authentication,usr_gamma,failure,85
2026-10-31 04:00:15,198.51.100.99,SSH Login Attempt,Authentication,usr_delta,failure,85
2026-10-31 04:00:20,198.51.100.99,SSH Login Attempt,Authentication,usr_epsilon,failure,85
"""
    res = client.post("/api/ingestion/import", json={
        "content": spray_csv,
        "format": "canonical_csv",
        "filename": "spray_test.csv"
    }, headers={"X-CSRFToken": token})

    assert res.status_code == 201
    data = res.get_json()
    assert data["accepted_records"] == 5
    assert data["correlated_alerts_generated"] >= 1

    # Verify detection alert created in database
    conn = get_db_connection(test_env["db_path"])
    c = conn.cursor()
    c.execute("SELECT id, alert_id, rule_name, matched_count, status FROM detection_alerts")
    alerts = c.fetchall()
    assert len(alerts) >= 1
    spray_alert = [a for a in alerts if "Password Spray" in a["rule_name"]][0]
    assert spray_alert["matched_count"] == 5
    assert spray_alert["status"] == "open"
    conn.close()


def test_dry_run_import_does_not_mutate_database(test_env):
    """Dry-run import parses and validates telemetry without creating any records."""
    client = test_env["client"]
    token = login_user(client)

    csv_data = """timestamp,source_ip,attack,username,outcome,risk
2026-10-31 18:00:00,10.0.0.99,Test Attack,testuser,failure,70
"""
    res = client.post("/api/ingestion/import", json={
        "content": csv_data,
        "format": "canonical_csv",
        "dry_run": True
    }, headers={"X-CSRFToken": token})

    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "dry_run"
    assert data["total_records_found"] == 1

    conn = get_db_connection(test_env["db_path"])
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS c FROM security_events")
    assert c.fetchone()["c"] == 0
    c.execute("SELECT COUNT(*) AS c FROM ingestion_batches")
    assert c.fetchone()["c"] == 0
    conn.close()


def test_path_traversal_filename_sanitization(test_env):
    """Uploaded filename with directory traversal characters is safely sanitized."""
    client = test_env["client"]
    token = login_user(client)

    csv_data = """timestamp,source_ip,attack,username,outcome,risk
2026-10-31 19:00:00,10.0.0.50,Path Traversal Test,tester,failure,50
"""
    res = client.post("/api/ingestion/import", json={
        "content": csv_data,
        "format": "canonical_csv",
        "filename": "../../etc/shadow"
    }, headers={"X-CSRFToken": token})

    assert res.status_code == 201
    batch_id = res.get_json()["batch_id"]

    conn = get_db_connection(test_env["db_path"])
    c = conn.cursor()
    c.execute("SELECT filename FROM ingestion_batches WHERE batch_id = ?", (batch_id,))
    stored_name = c.fetchone()["filename"]
    assert "/" not in stored_name
    assert "\\" not in stored_name
    assert ".." not in stored_name
    conn.close()


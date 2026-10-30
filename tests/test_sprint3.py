import pytest
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, evaluate_detection_pipeline

@pytest.fixture
def test_env(tmp_path):
    """Isolated database and test client with CSRF disabled for unit tests."""
    db_file = tmp_path / "test_sprint3.db"
    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "AdminPassword2026!",
        "SECRET_KEY": "sprint3-test-secret-key",
        "ENABLE_EXTERNAL_GEOIP": False,
    }
    app = create_app(test_config=config)
    with app.test_client() as client:
        yield client, config, str(db_file), app

@pytest.fixture
def authed_admin(test_env):
    """Pre-authenticated administrator client."""
    client, config, db_path, app = test_env
    res = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "AdminPassword2026!"
    })
    assert res.status_code == 200
    return client, config, db_path, app

@pytest.fixture
def authed_analyst(test_env):
    """Pre-authenticated analyst client."""
    client, config, db_path, app = test_env
    res = client.post("/api/auth/login", json={
        "username": "analyst_john",
        "password": "AnalystJohn2026!"
    })
    assert res.status_code == 200
    return client, config, db_path, app

# =========================================================================
# FEATURE 1 & 4: RULES RETRIEVAL & DEFAULT MITRE ATT&CK MAPPINGS
# =========================================================================

def test_seeded_rules_and_mitre_mappings(authed_admin):
    """Verify that the 6 default detection rules are seeded with valid MITRE ATT&CK mappings."""
    client, _, _, _ = authed_admin
    res = client.get("/api/detection/rules")
    assert res.status_code == 200
    data = res.get_json()
    rules = data["rules"] if "rules" in data else data
    assert len(rules) >= 6

    rule_ids = {r["rule_id"] for r in rules}
    expected_ids = {
        "RULE-AUTH-001", "RULE-NET-002", "RULE-EXPLOIT-003",
        "RULE-BURST-004", "RULE-BEHAV-005", "RULE-KERB-006"
    }
    assert expected_ids.issubset(rule_ids)

    # Verify MITRE ATT&CK technique mappings and valid HTTPS URLs
    for rule in rules:
        assert rule["mitre_technique_id"].startswith("T")
        assert len(rule["mitre_technique_name"]) > 0
        assert len(rule["mitre_tactic"]) > 0
        assert rule["mitre_url"].startswith("https://attack.mitre.org/techniques/T")
        assert rule["status"] == "enabled"
        assert rule["threshold"] >= 1
        assert rule["time_window_seconds"] >= 10
        assert isinstance(rule["conditions"], list)

def test_rule_filtering(authed_admin):
    """Verify rules can be filtered by severity, status, and search string."""
    client, _, _, _ = authed_admin
    # Filter by severity
    res = client.get("/api/detection/rules?severity=high")
    assert res.status_code == 200
    data = res.get_json()
    rules = data["rules"] if "rules" in data else data
    for r in rules:
        assert r["severity"] == "high"

    # Filter by status
    res = client.get("/api/detection/rules?status=enabled")
    assert res.status_code == 200
    data = res.get_json()
    rules = data["rules"] if "rules" in data else data
    assert len(rules) >= 6

    # Search query
    res = client.get("/api/detection/rules?search=Kerberos")
    assert res.status_code == 200
    data = res.get_json()
    found = data["rules"] if "rules" in data else data
    assert len(found) >= 1
    assert any("Kerb" in r["name"] or "Kerb" in r["description"] for r in found)

def test_get_single_rule_detail(authed_admin):
    """Verify detailed rule retrieval with parsed conditions and execution audit log."""
    client, _, _, _ = authed_admin
    res = client.get("/api/detection/rules/RULE-AUTH-001")
    assert res.status_code == 200
    data = res.get_json()
    rule = data.get("rule", data)
    assert rule["rule_id"] == "RULE-AUTH-001"
    assert rule["group_by_field"] == "username"
    assert len(rule["conditions"]) == 2

# =========================================================================
# FEATURE 5: SAFE RULE CRUD & RBAC (NO EVAL, ZERO ARBITRARY CODE)
# =========================================================================

def test_create_rule_admin_required(test_env):
    """Verify only admin can create custom detection rules (analysts receive 403, unauth receives 401)."""
    _, _, _, app = test_env

    new_rule = {
        "rule_id": "RULE-CUSTOM-001",
        "name": "Custom Privileged Session Spawning",
        "description": "Flags session token creation for sudo actions",
        "severity": "high",
        "conditions": [
            {"field": "behavior", "operator": "eq", "value": "privilege_escalation"},
            {"field": "risk", "operator": "gte", "value": 75}
        ],
        "threshold": 2,
        "time_window_seconds": 180,
        "group_by_field": "username",
        "mitre_technique_id": "T1548.003",
        "mitre_technique_name": "Sudo and Sudo Caching",
        "mitre_tactic": "Privilege Escalation",
        "mitre_url": "https://attack.mitre.org/techniques/T1548/003/"
    }

    # 1. Unauthenticated client
    unauth = app.test_client()
    res = unauth.post("/api/detection/rules", json=new_rule)
    assert res.status_code == 401

    # 2. Authenticate as analyst
    analyst = app.test_client()
    analyst.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})
    res = analyst.post("/api/detection/rules", json=new_rule)
    assert res.status_code == 403

    # 3. Authenticate as admin
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})
    res = admin.post("/api/detection/rules", json=new_rule)
    assert res.status_code == 201
    created = res.get_json()
    assert created["rule"]["rule_id"] == "RULE-CUSTOM-001"
    assert created["rule"]["version"] == 1

def test_safe_condition_validation_rejects_eval_and_malformed_inputs(authed_admin):
    """Strictly reject unauthorized fields, malicious operators, or boolean threshold parameters."""
    client, _, _, _ = authed_admin

    # 1. Invalid field (e.g. attempting SQL injection or eval)
    res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-BAD-1",
        "name": "Invalid field injection",
        "conditions": [{"field": "__class__", "operator": "eq", "value": "hack"}]
    })
    assert res.status_code == 400
    assert "Invalid rule condition field" in res.get_json()["error"] or "invalid field" in res.get_json()["message"]

    # 2. Invalid operator
    res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-BAD-2",
        "name": "Invalid operator injection",
        "conditions": [{"field": "attack", "operator": "eval", "value": "print('hack')"}]
    })
    assert res.status_code == 400
    assert "invalid operator" in res.get_json()["message"].lower()

    # 3. Boolean threshold parameter (type-coercion vulnerability test)
    res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-BAD-3",
        "name": "Boolean threshold exploit",
        "conditions": [{"field": "attack", "operator": "contains", "value": "test"}],
        "threshold": True
    })
    assert res.status_code == 400
    assert "boolean" in res.get_json()["message"].lower()

    # 4. Insecure MITRE URL (non-HTTPS or external phishing domain)
    res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-BAD-4",
        "name": "Untrusted MITRE URL",
        "conditions": [{"field": "attack", "operator": "contains", "value": "test"}],
        "mitre_url": "http://evil-site.com/exploit"
    })
    assert res.status_code == 400
    assert "https://attack.mitre.org/" in res.get_json()["message"]

def test_rule_update_with_optimistic_locking(authed_admin):
    """Verify rule editing enforces optimistic version locking."""
    client, _, _, _ = authed_admin

    # Create rule
    res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-OPT-001",
        "name": "Optimistic Locking Rule",
        "conditions": [{"field": "risk", "operator": "gte", "value": 50}],
        "threshold": 1,
        "time_window_seconds": 60
    })
    assert res.status_code == 201
    assert res.get_json()["rule"]["version"] == 1

    # Stale version update should fail with 409
    res = client.put("/api/detection/rules/RULE-OPT-001", json={
        "name": "Stale Update",
        "version": 999
    })
    assert res.status_code == 409

    # Valid version update succeeds and increments version
    res = client.put("/api/detection/rules/RULE-OPT-001", json={
        "name": "Updated Optimistic Locking Rule",
        "threshold": 5,
        "version": 1
    })
    assert res.status_code == 200
    assert res.get_json()["rule"]["version"] == 2
    assert res.get_json()["rule"]["threshold"] == 5

def test_rule_toggle_and_delete(authed_admin):
    """Verify toggling enabled/disabled status and deletion."""
    client, _, _, _ = authed_admin

    res = client.post("/api/detection/rules/RULE-BURST-004/toggle")
    assert res.status_code == 200
    assert res.get_json()["status"] == "disabled"

    res = client.post("/api/detection/rules/RULE-BURST-004/toggle")
    assert res.status_code == 200
    assert res.get_json()["status"] == "enabled"

    # Delete custom rule
    client.post("/api/detection/rules", json={
        "rule_id": "RULE-DEL-001",
        "name": "Rule to delete",
        "conditions": [{"field": "risk", "operator": "gte", "value": 10}]
    })
    del_res = client.delete("/api/detection/rules/RULE-DEL-001")
    assert del_res.status_code == 200

# =========================================================================
# FEATURE 2: THREAT CORRELATION & SLIDING TIME WINDOW ENGINE
# =========================================================================

def test_correlation_single_event_immediate_alert(authed_admin):
    """A rule with threshold=1 triggers an alert immediately upon log creation."""
    client, _, _, _ = authed_admin

    # RULE-EXPLOIT-003: threshold=1, risk >= 80, severity critical
    sim_res = client.post("/api/incidents/simulate", json={
        "attack": "Zero-Day Kernel Exploit",
        "risk": 95,
        "behavior": "privilege_escalation",
        "city": "Frankfurt, Germany"
    })
    assert sim_res.status_code == 201

    # Check alert was generated
    alert_res = client.get("/api/detection/alerts?severity=critical")
    assert alert_res.status_code == 200
    alerts = alert_res.get_json()["alerts"]
    assert len(alerts) >= 1
    matched = [a for a in alerts if a["rule_id"] == "RULE-EXPLOIT-003" or a.get("rule_code") == "RULE-EXPLOIT-003" or a.get("severity") == "critical"]
    assert len(matched) >= 1
    alert = matched[0]
    assert alert["severity"] == "critical"

def test_sliding_window_group_by_threshold(authed_admin):
    """Verify group-by entity correlation respects sliding window and threshold count."""
    client, _, db_path, app = authed_admin

    # Create a rule: threshold=3, time_window=120s, group_by=ip
    client.post("/api/detection/rules", json={
        "rule_id": "RULE-TEST-IP-CORR",
        "name": "Multi-event IP Correlation",
        "severity": "high",
        "conditions": [
            {"field": "attack", "operator": "contains", "value": "PortScan"}
        ],
        "threshold": 3,
        "time_window_seconds": 120,
        "group_by_field": "ip"
    })

    target_ip = "192.0.2.100"
    other_ip = "192.0.2.200"

    with app.app_context():
        db = get_db_connection(db_path)
        now = datetime.now()
        # Insert 2 events from target_ip (threshold is 3, so should NOT trigger yet)
        db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now.strftime("%Y-%m-%d %H:%M:%S"), target_ip, "PortScan TCP", 50, "reconnaissance", "London", "target1", 1)
        )
        db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now.strftime("%Y-%m-%d %H:%M:%S"), target_ip, "PortScan UDP", 50, "reconnaissance", "London", "target1", 1)
        )
        # Insert 1 event from other_ip (should not group into target_ip)
        db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now.strftime("%Y-%m-%d %H:%M:%S"), other_ip, "PortScan TCP", 50, "reconnaissance", "London", "target1", 1)
        )
        db.commit()

        # Trigger evaluation on target_ip
        cur = db.execute("SELECT id FROM logs WHERE ip = ? ORDER BY id DESC LIMIT 1", (target_ip,))
        last_id = cur.fetchone()["id"]
        alerts = evaluate_detection_pipeline([last_id], db_path)
        matching_alerts = [a for a in alerts if a["rule_id"] == "RULE-TEST-IP-CORR"]
        assert len(matching_alerts) == 0  # Only 2 events, threshold is 3

        # Add 3rd event from target_ip
        db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now.strftime("%Y-%m-%d %H:%M:%S"), target_ip, "PortScan SYN", 55, "reconnaissance", "London", "target1", 1)
        )
        db.commit()
        cur = db.execute("SELECT id FROM logs WHERE ip = ? ORDER BY id DESC LIMIT 1", (target_ip,))
        third_id = cur.fetchone()["id"]
        alerts = evaluate_detection_pipeline([third_id], db_path)
        matching_alerts = [a for a in alerts if a["rule_id"] == "RULE-TEST-IP-CORR"]
        assert len(matching_alerts) == 1
        assert matching_alerts[0]["rule_id"] == "RULE-TEST-IP-CORR"
        assert matching_alerts[0]["group_key"] == target_ip
        assert matching_alerts[0]["incident_count"] == 3

def test_idempotency_prevents_duplicate_alerts(authed_admin):
    """Re-evaluating the same telemetry events within the same time window produces no duplicate alerts."""
    client, _, db_path, app = authed_admin

    with app.app_context():
        db = get_db_connection(db_path)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now, "198.51.100.1", "Kernel Exploit", 90, "privilege_escalation", "Berlin", "root", 1)
        )
        db.commit()
        log_id = cur.lastrowid

        # First evaluation generates 1 alert
        a1 = evaluate_detection_pipeline([log_id], db_path)
        assert len(a1) == 1

        # Second evaluation on same log produces 0 alerts (idempotent)
        a2 = evaluate_detection_pipeline([log_id], db_path)
        assert len(a2) == 0

# =========================================================================
# FEATURE 3: ALERTS WORKSPACE, EXPLAINABILITY & CASE ESCALATION
# =========================================================================

def test_alert_details_and_escalate_to_case(authed_admin):
    """Verify alert explainability inspection and 1-click case escalation."""
    client, _, _, _ = authed_admin

    # Trigger a replay to guarantee alerts exist
    client.post("/api/detection/replay", json={"preset": "credential_spray"})

    # Fetch alerts
    res = client.get("/api/detection/alerts")
    assert res.status_code == 200
    alerts = res.get_json()["alerts"]
    assert len(alerts) >= 1

    alert = alerts[0]
    alert_id = alert["alert_id"]

    # Inspect single alert
    detail_res = client.get(f"/api/detection/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.get_json()["alert"]
    assert detail["alert_id"] == alert_id
    assert "explanation" in detail
    assert "incidents" in detail
    assert len(detail["incidents"]) >= 1

    # Escalate alert to SOC investigation case
    esc_res = client.post(f"/api/detection/alerts/{alert_id}/escalate")
    assert esc_res.status_code == 200
    esc_data = esc_res.get_json()
    assert esc_data["status"] == "escalated"
    assert "case_id" in esc_data
    case_id = esc_data["case_id"]

    # Verify case exists in cases table
    case_res = client.get(f"/api/incidents/{case_id}/case")
    assert case_res.status_code == 200
    assert case_res.get_json()["case"]["incident_id"] == case_id

    # Verify alert state in alert detail
    updated_alert = client.get(f"/api/detection/alerts/{alert_id}").get_json()["alert"]
    assert updated_alert["status"] == "escalated"
    assert updated_alert.get("case_id") == case_id or updated_alert.get("linked_incident_id") == case_id

def test_close_alert(authed_admin):
    """Verify closing an alert without case escalation."""
    client, _, _, _ = authed_admin
    client.post("/api/detection/replay", json={"preset": "recon_burst"})

    res = client.get("/api/detection/alerts?status=open")
    alerts = res.get_json()["alerts"]
    assert len(alerts) >= 1
    alert_id = alerts[0]["alert_id"]

    close_res = client.post(f"/api/detection/alerts/{alert_id}/close")
    assert close_res.status_code == 200
    assert close_res.get_json()["status"] == "closed"

# =========================================================================
# FEATURE 6: SYNTHETIC REPLAY PIPELINE
# =========================================================================

def test_synthetic_replay_presets(authed_admin):
    """Verify synthetic scenario replay generates expected incidents with provenance and alerts."""
    client, _, _, _ = authed_admin

    # 1. Credential spray preset
    res = client.post("/api/detection/replay", json={"preset": "credential_spray"})
    assert res.status_code == 201
    data = res.get_json()
    assert data["incidents_created"] == 3
    assert data["alerts_generated"] >= 1

    # 2. Recon burst preset
    res = client.post("/api/detection/replay", json={"preset": "recon_burst"})
    assert res.status_code == 201
    assert res.get_json()["incidents_created"] == 3

    # 3. Lateral exploit preset
    res = client.post("/api/detection/replay", json={"preset": "lateral_exploit"})
    assert res.status_code == 201
    assert res.get_json()["incidents_created"] == 1

    # 4. Kerberoasting preset
    res = client.post("/api/detection/replay", json={"preset": "kerberoast"})
    assert res.status_code == 201
    assert res.get_json()["incidents_created"] == 1

# =========================================================================
# FEATURE 7: DETECTION ANALYTICS & METRICS
# =========================================================================

def test_detection_metrics_endpoint(authed_admin):
    """Verify aggregated metrics endpoint returns persisted counts, severity distribution, and top rules."""
    client, _, _, _ = authed_admin
    res = client.get("/api/detection/metrics")
    assert res.status_code == 200
    metrics = res.get_json()
    assert "total_rules" in metrics
    assert "active_rules" in metrics
    assert "total_alerts" in metrics
    assert "open_alerts" in metrics
    assert "severity_breakdown" in metrics
    assert "top_triggered_rules" in metrics
    assert metrics["active_rules"] >= 6

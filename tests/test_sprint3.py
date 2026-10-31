import pytest
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, evaluate_detection_pipeline, init_db

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
    """Verify toggling enabled/disabled status and soft deletion / archival."""
    client, _, _, _ = authed_admin

    res = client.post("/api/detection/rules/RULE-BURST-004/toggle")
    assert res.status_code == 200
    assert res.get_json()["status"] == "disabled"

    res = client.post("/api/detection/rules/RULE-BURST-004/toggle")
    assert res.status_code == 200
    assert res.get_json()["status"] == "enabled"

    # Soft delete / archive custom rule
    client.post("/api/detection/rules", json={
        "rule_id": "RULE-DEL-001",
        "name": "Rule to delete",
        "conditions": [{"field": "risk", "operator": "gte", "value": 10}]
    })
    del_res = client.delete("/api/detection/rules/RULE-DEL-001")
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "success"
    assert del_res.get_json()["rule"]["status"] == "archived"

# =========================================================================
# FEATURE 2: THREAT CORRELATION & SLIDING TIME WINDOW ENGINE
# =========================================================================

def test_correlation_single_event_immediate_alert(authed_admin):
    """A rule with threshold=1 triggers an alert immediately upon log creation."""
    client, _, _, _ = authed_admin

    # RULE-EXPLOIT-003: threshold=1, risk >= 75, attack contains 'Lateral'
    sim_res = client.post("/api/incidents/simulate", json={
        "attack": "Lateral SMB Named Pipe Impersonation",
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
            (now, "198.51.100.1", "Lateral SMB Named Pipe Exploit", 90, "privilege_escalation", "Berlin", "root", 1)
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
    assert "evaluated_events" in metrics
    assert "total_events_stored" in metrics
    assert metrics["evaluated_events"] == metrics["total_events_stored"]


# =========================================================================
# SPRINT 3 POST-INTEGRATION CORRECTIONS & REGRESSION SUITE
# =========================================================================

def test_soft_deletion_preserves_historical_alerts_and_audit_log(authed_admin):
    """Archiving a rule stops evaluation but preserves all historical alerts, execution history, and audit log entries."""
    client, _, db_path, app = authed_admin

    # 1. Create a custom rule
    c_res = client.post("/api/detection/rules", json={
        "rule_id": "RULE-ARCHIVE-TEST",
        "name": "Archival Retention Rule",
        "severity": "medium",
        "conditions": [{"field": "attack", "operator": "contains", "value": "ArchiveTrigger"}],
        "threshold": 1,
        "time_window_seconds": 60
    })
    assert c_res.status_code == 201

    # 2. Trigger an incident to generate an alert from this rule
    with app.app_context():
        db = get_db_connection(db_path)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now, "10.10.10.10", "ArchiveTrigger Event", 60, "test_behavior", "Dallas", "user_arch", 1)
        )
        db.commit()
        log_id = cur.lastrowid
        alerts = evaluate_detection_pipeline([log_id], db_path)
        assert len(alerts) >= 1
        matching = [a for a in alerts if a["rule_id"] == "RULE-ARCHIVE-TEST"]
        assert len(matching) == 1
        generated_alert_id = matching[0]["alert_id"]

    # 3. Administratively archive the rule via DELETE endpoint
    del_res = client.delete("/api/detection/rules/RULE-ARCHIVE-TEST")
    assert del_res.status_code == 200
    del_data = del_res.get_json()
    assert del_data["status"] == "success"
    assert del_data["rule"]["status"] == "archived"

    # 4. Verify rule is marked as archived in GET
    detail_res = client.get("/api/detection/rules/RULE-ARCHIVE-TEST")
    assert detail_res.status_code == 200
    rule_detail = detail_res.get_json()["rule"]
    assert rule_detail["status"] == "archived"
    assert any(a["action"] == "archived" for a in rule_detail["audit_log"])

    # 5. Verify the historical alert STILL EXISTS and is fully accessible
    alert_get = client.get(f"/api/detection/alerts/{generated_alert_id}")
    assert alert_get.status_code == 200
    assert alert_get.get_json()["alert"]["alert_id"] == generated_alert_id

    # 6. Verify archived rule DOES NOT EXECUTE on new incoming events
    with app.app_context():
        db = get_db_connection(db_path)
        now2 = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur2 = db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now2, "10.10.10.11", "ArchiveTrigger Event 2", 65, "test_behavior", "Dallas", "user_arch", 1)
        )
        db.commit()
        log_id2 = cur2.lastrowid
        new_alerts = evaluate_detection_pipeline([log_id2], db_path)
        archived_rule_alerts = [a for a in new_alerts if a["rule_id"] == "RULE-ARCHIVE-TEST"]
        assert len(archived_rule_alerts) == 0  # Must not fire while archived!


def test_rule_specificity_and_distinct_behaviors(authed_admin):
    """Verify rules enforce genuine behavior attributes and multi-behavior rules require distinct behavior values."""
    client, _, db_path, app = authed_admin

    with app.app_context():
        db = get_db_connection(db_path)
        now = datetime.now()

        # 1. Port scan rule (RULE-NET-002) requires scan/recon behavior, not merely high risk!
        # Insert 3 high-risk events without scan behavior -> Should NOT trigger RULE-NET-002
        test_ip = "192.168.99.1"
        for i in range(3):
            t_str = (now - timedelta(seconds=20 * (3 - i))).strftime("%Y-%m-%d %H:%M:%S")
            db.execute("""
                INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated)
                VALUES (?, ?, 'High Risk Action', 70, 'generic_action', 'Tokyo', 'user1', 1)
            """, (t_str, test_ip))
        db.commit()
        cur = db.execute("SELECT id FROM logs WHERE ip = ? ORDER BY id DESC LIMIT 1", (test_ip,))
        last_id = cur.fetchone()["id"]
        res_alerts = evaluate_detection_pipeline([last_id], db_path)
        net_alerts = [a for a in res_alerts if a["rule_id"] == "RULE-NET-002"]
        assert len(net_alerts) == 0  # No scan behavior -> No port scan alert!

        # 2. Multi-behavior rule (RULE-BEHAV-005) requires distinct behaviors:
        # 2 events with identical behavior 'manual' -> Should NOT trigger
        test_user = "user_same_behav"
        for i in range(2):
            t_str = (now - timedelta(seconds=15 * (2 - i))).strftime("%Y-%m-%d %H:%M:%S")
            db.execute("""
                INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated)
                VALUES (?, '10.0.0.1', 'Action', 50, 'manual', 'London', ?, 1)
            """, (t_str, test_user))
        db.commit()
        cur = db.execute("SELECT id FROM logs WHERE username = ? ORDER BY id DESC LIMIT 1", (test_user,))
        last_id = cur.fetchone()["id"]
        res_alerts2 = evaluate_detection_pipeline([last_id], db_path)
        behav_alerts = [a for a in res_alerts2 if a["rule_id"] == "RULE-BEHAV-005"]
        assert len(behav_alerts) == 0  # Identical behaviors do not satisfy multi-behavior rule

        # Now add an event with a DIFFERENT behavior ('privilege_escalation')
        t_str_diff = now.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("""
            INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated)
            VALUES (?, '10.0.0.1', 'Privilege Step', 60, 'privilege_escalation', 'London', ?, 1)
        """, (t_str_diff, test_user))
        db.commit()
        cur = db.execute("SELECT id FROM logs WHERE username = ? ORDER BY id DESC LIMIT 1", (test_user,))
        diff_id = cur.fetchone()["id"]
        res_alerts3 = evaluate_detection_pipeline([diff_id], db_path)
        behav_alerts2 = [a for a in res_alerts3 if a["rule_id"] == "RULE-BEHAV-005"]
        assert len(behav_alerts2) == 1  # 2 distinct behaviors ('manual', 'privilege_escalation') -> Triggers!


def test_alert_correlation_update_and_deduplication(authed_admin):
    """Adding new events to an active correlation window updates the existing alert without creating duplicate alert storms."""
    client, _, _, _ = authed_admin

    # Run replay once
    res1 = client.post("/api/detection/replay", json={"preset": "recon_burst"})
    assert res1.status_code == 201

    alerts_res1 = client.get("/api/detection/alerts?severity=medium")
    alerts1 = alerts_res1.get_json()["alerts"]
    recon_alerts1 = [a for a in alerts1 if a["rule_id"] == "RULE-NET-002" or a.get("rule_code") == "RULE-NET-002"]
    assert len(recon_alerts1) >= 1
    initial_alert = recon_alerts1[0]
    initial_count = initial_alert["matched_count"]

    # Run replay a second time with same preset
    res2 = client.post("/api/detection/replay", json={"preset": "recon_burst"})
    assert res2.status_code == 201

    alerts_res2 = client.get("/api/detection/alerts?severity=medium")
    alerts2 = alerts_res2.get_json()["alerts"]
    recon_alerts2 = [a for a in alerts2 if a["rule_id"] == "RULE-NET-002" or a.get("rule_code") == "RULE-NET-002"]

    # Active correlation update: The existing alert is updated, preventing duplicate alert storm
    assert len(recon_alerts2) == len(recon_alerts1)
    updated_alert = [a for a in recon_alerts2 if a["alert_id"] == initial_alert["alert_id"]][0]
    assert updated_alert["matched_count"] >= initial_count


def test_alert_escalation_authorization_and_cross_analyst_protection(test_env):
    """Verify alert escalation validates target incident existence, relationship to alert, and cross-analyst ownership."""
    client, _, db_path, app = test_env

    # Admin client creates a replay alert
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})
    rep_res = admin.post("/api/detection/replay", json={"preset": "credential_spray"})
    assert rep_res.status_code == 201

    alerts_res = admin.get("/api/detection/alerts")
    alert = alerts_res.get_json()["alerts"][0]
    alert_id = alert["alert_id"]
    matched_ids = alert["matched_incident_ids"]

    # 1. Invalid incident ID (non-existent) rejected
    bad_res = admin.post(f"/api/detection/alerts/{alert_id}/escalate", json={"incident_id": 999999})
    assert bad_res.status_code in (400, 404)

    # 2. Unrelated incident ID (exists but not part of this alert) rejected
    with app.app_context():
        db = get_db_connection(db_path)
        cur = db.execute(
            "INSERT INTO logs (time, ip, attack, risk, behavior, location, username, is_simulated) VALUES ('2026-10-31 00:00:00', '1.1.1.1', 'Other', 20, 'none', 'Paris', 'other_user', 1)"
        )
        db.commit()
        unrelated_id = cur.lastrowid

    unrel_res = admin.post(f"/api/detection/alerts/{alert_id}/escalate", json={"incident_id": unrelated_id})
    assert unrel_res.status_code == 400
    assert "not part of this alert" in unrel_res.get_json()["message"]

    # 3. Cross-analyst escalation protection:
    # Assign target incident's case to analyst_jane
    target_id = matched_ids[0]
    with app.app_context():
        db = get_db_connection(db_path)
        # Find analyst_jane id
        jane_row = db.execute("SELECT id FROM users WHERE username = 'analyst_jane'").fetchone()
        jane_id = jane_row["id"]
        db.execute("UPDATE cases SET assigned_to = ?, assigned_username = 'analyst_jane' WHERE incident_id = ?", (jane_id, target_id))
        db.commit()

    # Now login as analyst_john (different analyst)
    john = app.test_client()
    john.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})
    john_res = john.post(f"/api/detection/alerts/{alert_id}/escalate", json={"incident_id": target_id})
    assert john_res.status_code == 403
    assert "assigned to another analyst" in john_res.get_json()["message"]

    # 4. Valid escalation by Admin or assigned analyst succeeds
    admin_esc = admin.post(f"/api/detection/alerts/{alert_id}/escalate", json={"incident_id": target_id})
    assert admin_esc.status_code == 200
    assert admin_esc.get_json()["status"] == "escalated"

    # 5. Repeated escalation to same incident is rejected with 409 Conflict
    repeat_res = admin.post(f"/api/detection/alerts/{alert_id}/escalate", json={"incident_id": target_id})
    assert repeat_res.status_code == 409


# =========================================================================
# SPRINT 3 POST-INTEGRATION HARDENING REGRESSION TESTS
# =========================================================================

def test_exact_detection_windows(authed_admin):
    """Verify that detection rules have exact window requirements:
    RULE-AUTH-001: 60s, RULE-NET-002: 45s, RULE-BURST-004: 120s, RULE-BEHAV-005: 180s.
    """
    client, _, _, _ = authed_admin
    res = client.get("/api/detection/rules")
    assert res.status_code == 200
    rules = {r["rule_id"]: r for r in res.get_json()["rules"]}

    assert rules["RULE-AUTH-001"]["time_window_seconds"] == 60
    assert rules["RULE-NET-002"]["time_window_seconds"] == 45
    assert rules["RULE-BURST-004"]["time_window_seconds"] == 120
    assert rules["RULE-BEHAV-005"]["time_window_seconds"] == 180


def test_multi_target_password_spray_requires_distinct_usernames(test_env):
    """RULE-BURST-004 must require genuinely distinct target usernames (>= 5),
    not merely 5 events against the same account.
    """
    client, _, db_path, app = test_env
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})

    now = datetime.now()

    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()

        # Part 1: Inject 5 auth attack events all targeting single user 'admin'
        # with attack containing 'Attempt' and risk >= 40 (satisfying condition, but not distinct targets)
        single_user_ids = []
        for i in range(5):
            t = (now - timedelta(seconds=10 * (5 - i))).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('admin', 'Credential Stuffing Attempt', 'auth_failure', 50, '198.51.100.10', 'Chicago', ?, 0, 1)
            """, (t,))
            log_id = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, t, t))
            single_user_ids.append(log_id)
        conn.commit()

        # Evaluate detection pipeline
        evaluate_detection_pipeline(single_user_ids, db_path)

        # Check alerts: RULE-BURST-004 should NOT trigger because only 1 unique user was targeted
        c.execute("""
            SELECT a.id, a.alert_id, r.rule_id, a.explanation
            FROM detection_alerts a
            JOIN detection_rules r ON a.rule_id = r.id
            WHERE r.rule_id = 'RULE-BURST-004'
        """)
        spray_alert = c.fetchone()
        assert spray_alert is None, "RULE-BURST-004 must not trigger on 5 events targeting the same username"

        # Part 2: Inject 5 events targeting 5 genuinely distinct usernames
        distinct_user_ids = []
        distinct_usernames = ["user_alice", "user_bob", "user_charlie", "user_dave", "user_eve"]
        for idx, u in enumerate(distinct_usernames):
            t = (now - timedelta(seconds=5 * (5 - idx))).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES (?, 'Password Spraying Attempt', 'auth_failure', 50, '198.51.100.20', 'Dallas', ?, 0, 1)
            """, (u, t))
            log_id = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (log_id, t, t))
            distinct_user_ids.append(log_id)
        conn.commit()

        # Evaluate detection pipeline
        evaluate_detection_pipeline(distinct_user_ids, db_path)

        # Check alerts: RULE-BURST-004 MUST now trigger on 5 distinct accounts
        c.execute("""
            SELECT a.id, a.alert_id, r.rule_id, a.explanation
            FROM detection_alerts a
            JOIN detection_rules r ON a.rule_id = r.id
            WHERE r.rule_id = 'RULE-BURST-004'
        """)
        spray_alert = c.fetchone()
        assert spray_alert is not None, "RULE-BURST-004 must trigger when distinct usernames are targeted"
        assert "distinct user accounts" in spray_alert["explanation"]
        conn.close()


def test_correlation_window_expiration_prevents_infinite_accumulation(test_env):
    """Old open detection alerts must not accumulate new events forever.
    When subsequent events fall outside the correlation window, a new alert is generated.
    """
    client, _, db_path, app = test_env
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})

    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()

        now = datetime.now()
        # Window for RULE-AUTH-001 is 60 seconds
        # First wave of 3 events occurred 180 seconds ago (-170s, -160s, -150s), safely outside the 60s cutoff
        wave1_ids = []
        for s in (10, 20, 30):
            t = (now - timedelta(seconds=180 - s)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('target_user', 'Credential Stuffing', 'brute_force', 70, '192.0.2.1', 'London', ?, 0, 1)
            """, (t,))
            lid = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (lid, t, t))
            wave1_ids.append(lid)
        conn.commit()

        evaluate_detection_pipeline(wave1_ids, db_path)

        # Verify initial alert created
        c.execute("""
            SELECT a.alert_id, a.matched_count
            FROM detection_alerts a
            JOIN detection_rules r ON a.rule_id = r.id
            WHERE r.rule_id = 'RULE-AUTH-001'
        """)
        alerts_wave1 = c.fetchall()
        assert len(alerts_wave1) == 1
        initial_alert_id = alerts_wave1[0]["alert_id"]
        assert alerts_wave1[0]["matched_count"] == 3

        # Second wave occurs within the recent sliding window (-25s, -20s, -15s), well past wave 1's window
        wave2_ids = []
        for s in (5, 10, 15):
            t = (now - timedelta(seconds=30 - s)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('target_user', 'Credential Stuffing', 'brute_force', 70, '192.0.2.1', 'London', ?, 0, 1)
            """, (t,))
            lid = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (lid, t, t))
            wave2_ids.append(lid)
        conn.commit()

        evaluate_detection_pipeline(wave2_ids, db_path)

        # Verify that the old alert did NOT accumulate the new events forever;
        # instead, a distinct alert was created for the new window
        c.execute("""
            SELECT a.alert_id, a.matched_count
            FROM detection_alerts a
            JOIN detection_rules r ON a.rule_id = r.id
            WHERE r.rule_id = 'RULE-AUTH-001'
            ORDER BY a.id ASC
        """)
        all_alerts = c.fetchall()
        assert len(all_alerts) == 2, "A new alert must be created once correlation window expires"
        assert all_alerts[0]["alert_id"] == initial_alert_id
        assert all_alerts[0]["matched_count"] == 3  # Unchanged
        assert all_alerts[1]["matched_count"] == 3  # Fresh window
        conn.close()


def test_evaluated_events_metric_accuracy(test_env):
    """The evaluated_events metric must accurately track the count of evaluated events
    in the evaluated_events table rather than simply returning total logs stored.
    """
    client, _, db_path, app = test_env
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})

    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()

        # Insert 4 historical logs directly without pipeline evaluation
        for i in range(4):
            t = (datetime.now() - timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
                INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
                VALUES ('dormant_user', 'Normal Probe', 'none', 10, '10.0.0.1', 'HQ', ?, 0, 1)
            """, (t,))
            lid = c.lastrowid
            c.execute("INSERT INTO cases (incident_id, status, created_at, updated_at) VALUES (?, 'new', ?, ?)", (lid, t, t))
        conn.commit()
        conn.close()

    # Query metrics before pipeline evaluation
    res = admin.get("/api/detection/metrics")
    assert res.status_code == 200
    metrics = res.get_json()
    assert metrics["total_events_stored"] >= 4
    # Evaluated events should be 0 because none passed through pipeline yet
    assert metrics["evaluated_events"] == 0

    # Now run synthetic replay which evaluates events through the pipeline
    replay_res = admin.post("/api/detection/replay", json={"preset": "credential_spray"})
    assert replay_res.status_code == 201

    res_after = admin.get("/api/detection/metrics")
    metrics_after = res_after.get_json()
    assert metrics_after["evaluated_events"] > 0
    assert metrics_after["evaluated_events"] <= metrics_after["total_events_stored"]


def test_sqlite_migration_foreign_key_integrity(test_env):
    """Verify historical SQLite migrations maintain valid foreign keys (PRAGMA foreign_key_check = 0)
    and preserve all audit records in rule_audit_log, incident_audit_log, and system_audit_log.
    """
    client, _, db_path, app = test_env
    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()

        # Check foreign key violations
        c.execute("PRAGMA foreign_key_check")
        fk_violations = c.fetchall()
        assert len(fk_violations) == 0, f"Foreign key check failed: {fk_violations}"

        # Verify audit log tables exist and are functional
        c.execute("SELECT COUNT(*) AS cnt FROM rule_audit_log")
        assert c.fetchone()["cnt"] >= 0

        c.execute("SELECT COUNT(*) AS cnt FROM incident_audit_log")
        assert c.fetchone()["cnt"] >= 0

        c.execute("SELECT COUNT(*) AS cnt FROM system_audit_log")
        assert c.fetchone()["cnt"] >= 0

        # Verify evaluated_events table exists with valid schema
        c.execute("PRAGMA table_info(evaluated_events)")
        cols = {row["name"]: row["type"].upper() for row in c.fetchall()}
        assert "incident_id" in cols
        assert "evaluated_at" in cols
        conn.close()


def test_populated_legacy_database_migration_and_foreign_key_enforcement(tmp_path):
    """Verify that a populated legacy SQLite database (Sprint 1/2 schema) is safely upgraded,
    preserving all existing records and passing PRAGMA foreign_key_check.
    Furthermore, verify that foreign key violations cause migration to fail loudly with RuntimeError
    rather than silently continuing.
    """
    db_file = tmp_path / "legacy_populated.db"
    conn = sqlite3.connect(str(db_file))
    c = conn.cursor()

    # Create baseline legacy schema (pre-Sprint 3)
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            ip TEXT NOT NULL,
            attack TEXT NOT NULL,
            risk INTEGER NOT NULL,
            behavior TEXT,
            location TEXT,
            resolved INTEGER DEFAULT 0,
            username TEXT,
            is_simulated INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE cases (
            incident_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'new',
            assigned_to INTEGER,
            assigned_username TEXT,
            assigned_at TEXT,
            investigation_started_at TEXT,
            contained_at TEXT,
            resolved_at TEXT,
            resolution_summary TEXT,
            reopen_count INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')
    c.execute('''
        CREATE TABLE incident_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            actor_id INTEGER,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            before_value TEXT,
            after_value TEXT,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')
    c.execute('''
        CREATE TABLE system_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Populate genuine legacy records
    c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES ('legacy_analyst', 'hash123', 'analyst', '2026-10-25 10:00:00')")
    user_id = c.lastrowid

    c.execute("INSERT INTO logs (time, ip, attack, risk, behavior, location, resolved, username, is_simulated) VALUES ('2026-10-25 10:05:00', '198.51.100.1', 'Brute Force', 80, 'auth_fail', 'Dallas', 0, 'victim', 0)")
    log_id = c.lastrowid

    c.execute("INSERT INTO cases (incident_id, status, assigned_to, assigned_username, created_at, updated_at) VALUES (?, 'new', ?, 'legacy_analyst', '2026-10-25 10:05:00', '2026-10-25 10:05:00')", (log_id, user_id))

    c.execute("INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, created_at) VALUES (?, ?, 'legacy_analyst', 'created', '2026-10-25 10:05:00')", (log_id, user_id))
    c.execute("INSERT INTO system_audit_log (actor_id, actor_username, action, details, created_at) VALUES (?, 'legacy_analyst', 'system_init', 'Pre-existing audit', '2026-10-25 10:00:00')", (user_id,))
    conn.commit()
    conn.close()

    # Part A: Run init_db migration on genuine populated database
    init_db(str(db_file), "development", False, False, "admin", "AdminPassword2026!")

    # Verify data preservation and migration success
    conn_migrated = get_db_connection(str(db_file))
    cur = conn_migrated.cursor()

    cur.execute("PRAGMA foreign_key_check")
    fk_checks = cur.fetchall()
    assert len(fk_checks) == 0, f"Foreign key checks failed after migration: {fk_checks}"

    cur.execute("SELECT COUNT(*) AS c FROM users WHERE username = 'legacy_analyst'")
    assert cur.fetchone()["c"] == 1

    cur.execute("SELECT COUNT(*) AS c FROM logs WHERE id = ?", (log_id,))
    assert cur.fetchone()["c"] == 1

    cur.execute("SELECT COUNT(*) AS c FROM cases WHERE incident_id = ?", (log_id,))
    assert cur.fetchone()["c"] == 1

    cur.execute("SELECT COUNT(*) AS c FROM incident_audit_log WHERE incident_id = ?", (log_id,))
    assert cur.fetchone()["c"] == 1

    cur.execute("SELECT COUNT(*) AS c FROM system_audit_log")
    assert cur.fetchone()["c"] == 1

    cur.execute("SELECT COUNT(*) AS c FROM detection_rules")
    assert cur.fetchone()["c"] >= 6
    conn_migrated.close()

    # Part B: Verify that foreign-key integrity violations CANNOT silently continue
    corrupt_db_file = tmp_path / "corrupt_fk.db"
    conn_corrupt = sqlite3.connect(str(corrupt_db_file))
    c2 = conn_corrupt.cursor()
    c2.execute("PRAGMA foreign_keys = OFF")
    c2.execute('''
        CREATE TABLE logs (id INTEGER PRIMARY KEY, time TEXT, ip TEXT, attack TEXT, risk INTEGER)
    ''')
    c2.execute('''
        CREATE TABLE cases (incident_id INTEGER PRIMARY KEY, status TEXT, FOREIGN KEY (incident_id) REFERENCES logs(id))
    ''')
    # Insert orphan case referencing non-existent incident_id 99999
    c2.execute("INSERT INTO cases (incident_id, status) VALUES (99999, 'new')")
    conn_corrupt.commit()
    conn_corrupt.close()

    # Running init_db MUST fail loudly with RuntimeError, not continue silently
    with pytest.raises(RuntimeError) as exc_info:
        init_db(str(corrupt_db_file), "development", False, False, "admin", "AdminPassword2026!")
    assert "foreign key integrity check failed" in str(exc_info.value)


def test_alert_escalation_case_assignment_version_increment_and_concurrency(test_env):
    """Automatic case assignment during alert escalation must increment cases.version,
    record an incident_audit_log entry, and enforce optimistic locking concurrency.
    """
    client, _, db_path, app = test_env
    admin = app.test_client()
    admin.post("/api/auth/login", json={"username": "testadmin", "password": "AdminPassword2026!"})

    # Trigger an alert via replay
    rep = admin.post("/api/detection/replay", json={"preset": "credential_spray"})
    assert rep.status_code == 201

    alerts_res = admin.get("/api/detection/alerts")
    alert = alerts_res.get_json()["alerts"][0]
    alert_id = alert["alert_id"]
    target_inc_id = alert["matched_incident_ids"][0]

    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT version, assigned_to FROM cases WHERE incident_id = ?", (target_inc_id,))
        case_before = c.fetchone()
        assert case_before["assigned_to"] is None
        initial_version = case_before["version"]
        conn.close()

    # Analyst escalates alert and claims case with matching version
    analyst = app.test_client()
    analyst.post("/api/auth/login", json={"username": "analyst_john", "password": "AnalystJohn2026!"})

    # Stale version check: pass version=999
    conflict_res = analyst.post(f"/api/detection/alerts/{alert_id}/escalate", json={
        "incident_id": target_inc_id,
        "version": 999
    })
    assert conflict_res.status_code == 409
    assert "Concurrent modification" in conflict_res.get_json()["message"]

    # Valid escalation with correct version
    esc_res = analyst.post(f"/api/detection/alerts/{alert_id}/escalate", json={
        "incident_id": target_inc_id,
        "version": initial_version
    })
    assert esc_res.status_code == 200
    assert esc_res.get_json()["status"] == "escalated"

    with app.app_context():
        conn = get_db_connection(db_path)
        c = conn.cursor()
        c.execute("SELECT version, assigned_username FROM cases WHERE incident_id = ?", (target_inc_id,))
        case_after = c.fetchone()
        assert case_after["assigned_username"] == "analyst_john"
        assert case_after["version"] == initial_version + 1, "Case version must increment upon auto-claim"

        # Verify audit log recorded the auto-assignment
        c.execute("""
            SELECT action, actor_username, description FROM incident_audit_log
            WHERE incident_id = ? AND action = 'assigned'
        """, (target_inc_id,))
        audit_entry = c.fetchone()
        assert audit_entry is not None
        assert audit_entry["actor_username"] == "analyst_john"
        conn.close()


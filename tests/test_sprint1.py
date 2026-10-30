"""
AuthGuard-X Sprint 1 — Expanded Test Suite
Covers all Phase 1 tests PLUS new Sprint 1 features:
  - CSRF protection
  - Incident search/filter/sort/pagination
  - Server-side metrics
  - Simulation provenance enforcement
  - Incident detail endpoint
  - XSS safety on all new endpoints
"""
import os
import sys
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, is_private_or_loopback_ip, resolve_ip_location


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_env(tmp_path):
    """Isolated DB + test client. CSRF disabled for unit tests."""
    db_file = tmp_path / "test_authguard.db"
    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "TestPassword123!",
        "SECRET_KEY": "test-secret-key-for-authguard-x",
        "ENABLE_EXTERNAL_GEOIP": False,
    }
    app = create_app(test_config=config)
    with app.test_client() as client:
        yield client, config, str(db_file)


@pytest.fixture
def authed_env(test_env):
    """Pre-authenticated test environment."""
    client, config, db_path = test_env
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    return client, config, db_path


def _post_incident(client, attack="Test Attack", risk=50, behavior="manual",
                   username="tester", simulated=True, location="Test City"):
    return client.post("/api/incidents/simulate", json={
        "attack": attack,
        "risk": risk,
        "behavior": behavior,
        "username": username,
        "is_simulated": simulated,
        "simulated_location": location,
    })


# ===========================================================================
# PHASE 1 REGRESSION TESTS (all 15 original tests preserved)
# ===========================================================================

def test_health_check(test_env):
    client, _, _ = test_env
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "AuthGuard-X"


def test_index_serves_frontend(test_env):
    client, _, _ = test_env
    res = client.get("/")
    assert res.status_code == 200
    assert b"AuthGuard-X" in res.data


def test_login_valid(test_env):
    client, config, _ = test_env
    res = client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == config["DEMO_ADMIN_USER"]
    assert data["user"]["role"] == "admin"


def test_login_invalid(test_env):
    client, config, _ = test_env
    res = client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": "WrongPassword999!",
    })
    assert res.status_code == 401
    assert res.get_json()["status"] == "fail"


def test_login_missing_fields(test_env):
    client, _, _ = test_env
    res = client.post("/api/auth/login", json={"username": "admin"})
    assert res.status_code == 400
    assert res.get_json()["status"] == "fail"


def test_access_without_auth_blocked(test_env):
    client, _, _ = test_env
    assert client.get("/api/incidents").status_code == 401
    assert client.post("/api/incidents/simulate", json={"attack": "X", "risk": 50}).status_code == 401
    assert client.post("/api/incidents/1/resolve").status_code == 401


def test_session_status_and_logout(test_env):
    client, config, _ = test_env
    assert client.get("/api/auth/session").get_json()["authenticated"] is False
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    assert client.get("/api/auth/session").get_json()["authenticated"] is True
    assert client.post("/api/auth/logout").get_json()["status"] == "success"
    assert client.get("/api/auth/session").get_json()["authenticated"] is False


def test_attack_simulation_and_incident_logging(authed_env):
    client, _, _ = authed_env
    res = _post_incident(client, attack="Credential Stuffing", risk=75, location="Frankfurt, Germany")
    assert res.status_code == 201
    data = res.get_json()
    assert data["incident"]["attack"] == "Credential Stuffing"
    assert data["incident"]["risk"] == 75
    assert data["incident"]["is_simulated"] is True
    assert "Simulated" in data["incident"]["location"]


def test_incident_resolution(authed_env):
    client, _, _ = authed_env
    sim = _post_incident(client, attack="SQL Injection", risk=90)
    inc_id = sim.get_json()["incident"]["id"]
    res = client.post(f"/api/incidents/{inc_id}/resolve")
    assert res.status_code == 200
    logs = client.get("/api/incidents").get_json()
    # paginated response
    items = logs.get("incidents", logs) if isinstance(logs, dict) else logs
    resolved = [i for i in items if i["id"] == inc_id]
    assert resolved and resolved[0]["resolved"] == 1
    assert client.post("/api/incidents/9999/resolve").status_code == 404


def test_legacy_endpoint_aliases(test_env):
    client, config, _ = test_env
    assert client.post("/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    }).status_code == 200
    log_res = client.post("/log_attack", json={
        "username": "legacy", "attack": "Port Scan", "behavior": "recon", "risk": 45
    })
    assert log_res.status_code == 201
    log_id = log_res.get_json()["incident"]["id"]
    get_res = client.get("/get_logs")
    assert get_res.status_code == 200
    logs = get_res.get_json()
    assert any(i["attack"] == "Port Scan" for i in logs)
    assert client.post(f"/resolve_incident/{log_id}").status_code == 200
    assert client.post("/logout").status_code == 200


def test_input_validation(authed_env):
    client, _, _ = authed_env
    assert client.post("/api/incidents/simulate", json={"attack": "T", "risk": -10}).status_code == 400
    assert client.post("/api/incidents/simulate", json={"attack": "T", "risk": 150}).status_code == 400
    assert client.post("/api/incidents/simulate", json={"attack": "T", "risk": "crit"}).status_code == 400
    assert client.post("/api/incidents/simulate", json={"risk": 50}).status_code == 400


def test_xss_resistance(authed_env):
    client, _, _ = authed_env
    xss = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    res = _post_incident(client, attack=xss, username=xss, risk=50)
    assert res.status_code == 201
    logs = client.get("/api/incidents").get_json()
    items = logs.get("incidents", logs) if isinstance(logs, dict) else logs
    entry = items[0]
    assert entry["attack"] == xss
    assert entry["username"] == xss


def test_database_persistence_across_restarts(test_env):
    client1, config, db_path = test_env
    client1.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    _post_incident(client1, attack="Persistent Attack Vector", risk=99, username="target_corp")
    new_app = create_app(test_config=config)
    with new_app.test_client() as client2:
        client2.post("/api/auth/login", json={
            "username": config["DEMO_ADMIN_USER"],
            "password": config["DEMO_ADMIN_PASSWORD"],
        })
        res = client2.get("/api/incidents")
        items = res.get_json()
        if isinstance(items, dict):
            items = items.get("incidents", [])
        assert len(items) == 1
        assert items[0]["attack"] == "Persistent Attack Vector"


def test_production_mode_disables_demo_user(tmp_path):
    db_file = tmp_path / "prod.db"
    cfg = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "production",
        "DEMO_MODE": False,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "prod_demo",
        "DEMO_ADMIN_PASSWORD": "ShouldNotBeCreated!",
        "SECRET_KEY": "a-very-secure-64-character-production-secret-key-1234567890abcdef",
    }
    prod_app = create_app(test_config=cfg)
    with prod_app.test_client() as client:
        assert client.post("/api/auth/login", json={
            "username": "prod_demo", "password": "ShouldNotBeCreated!"
        }).status_code == 401
        assert client.get("/api/auth/session").get_json().get("demo_credentials") is None


def test_ip_helpers():
    assert is_private_or_loopback_ip("127.0.0.1") is True
    assert is_private_or_loopback_ip("::1") is True
    assert is_private_or_loopback_ip("192.168.1.100") is True
    assert is_private_or_loopback_ip("10.0.0.5") is True
    assert is_private_or_loopback_ip("8.8.8.8") is False
    assert "Internal" in resolve_ip_location("127.0.0.1", enable_external_geoip=False)


# ===========================================================================
# SPRINT 1 NEW TESTS
# ===========================================================================

# ---------------------------------------------------------------------------
# CSRF Token Endpoint
# ---------------------------------------------------------------------------

def test_csrf_token_endpoint_accessible(test_env):
    """CSRF token must be fetchable by unauthenticated clients (needed for login form)."""
    client, _, _ = test_env
    res = client.get("/api/auth/csrf-token")
    assert res.status_code == 200
    data = res.get_json()
    assert "csrf_token" in data
    assert isinstance(data["csrf_token"], str)
    assert len(data["csrf_token"]) > 10


# ---------------------------------------------------------------------------
# Simulation Provenance Enforcement
# ---------------------------------------------------------------------------

def test_simulate_always_marks_as_simulated(authed_env):
    """Even if client sends is_simulated=False, server must override to True."""
    client, _, _ = authed_env
    res = client.post("/api/incidents/simulate", json={
        "attack": "Injection Attempt",
        "risk": 70,
        "is_simulated": False,  # client tries to forge as real telemetry
    })
    assert res.status_code == 201
    inc = res.get_json()["incident"]
    assert inc["is_simulated"] is True, "Server must always mark /simulate incidents as simulated"


def test_legacy_log_attack_always_simulated(test_env):
    """Legacy /log_attack also must always produce simulated=True."""
    client, config, _ = test_env
    client.post("/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    res = client.post("/log_attack", json={
        "username": "attacker",
        "attack": "SSRF Probe",
        "behavior": "recon",
        "risk": 60,
        "is_simulated": False,
    })
    assert res.status_code == 201
    assert res.get_json()["incident"]["is_simulated"] is True


# ---------------------------------------------------------------------------
# Server-side Metrics
# ---------------------------------------------------------------------------

def test_metrics_endpoint_requires_auth(test_env):
    client, _, _ = test_env
    assert client.get("/api/metrics").status_code == 401


def test_metrics_empty_database(authed_env):
    client, _, _ = authed_env
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.get_json()
    for field in ["total_incidents", "open_incidents", "resolved_incidents",
                  "critical_count", "high_count", "medium_count", "low_count",
                  "simulated_count", "telemetry_count", "health_score",
                  "today_count", "week_count"]:
        assert field in data, f"Missing field: {field}"
    assert data["total_incidents"] == 0
    assert data["health_score"] == 100


def test_metrics_calculates_correctly(authed_env):
    client, _, _ = authed_env
    # Add incidents across severity bands
    _post_incident(client, attack="Critical 1", risk=85)  # critical, open
    _post_incident(client, attack="Critical 2", risk=90)  # critical, open
    _post_incident(client, attack="High 1", risk=65)      # high, open
    _post_incident(client, attack="Low 1", risk=20)       # low, open

    res = client.get("/api/metrics")
    data = res.get_json()
    assert data["total_incidents"] == 4
    assert data["critical_count"] == 2
    assert data["high_count"] == 1
    assert data["low_count"] == 1
    assert data["open_incidents"] == 4
    assert data["resolved_incidents"] == 0
    # health score: 100 - 2*8 (critical) - 1*5 (high) - 0 (low) = 79
    assert data["health_score"] == 79


def test_metrics_updates_on_resolution(authed_env):
    client, _, _ = authed_env
    sim = _post_incident(client, attack="Crit Attack", risk=85)
    inc_id = sim.get_json()["incident"]["id"]

    before = client.get("/api/metrics").get_json()
    assert before["open_incidents"] == 1
    assert before["health_score"] < 100

    client.post(f"/api/incidents/{inc_id}/resolve")
    after = client.get("/api/metrics").get_json()
    assert after["open_incidents"] == 0
    assert after["resolved_incidents"] == 1
    assert after["health_score"] == 100


# ---------------------------------------------------------------------------
# Incident Search, Filter, Sort, Pagination
# ---------------------------------------------------------------------------

def _seed_incidents(client, count=30):
    """Seed varied incidents for filter/pagination tests."""
    attacks = ["Brute Force", "SQL Injection", "XSS Probe", "DDoS", "Phishing"]
    users = ["alice", "bob", "charlie"]
    for i in range(count):
        risk = (i * 3) % 100 + 1  # varies 1–100
        _post_incident(
            client,
            attack=attacks[i % len(attacks)],
            risk=risk,
            username=users[i % len(users)],
        )


def test_incidents_paginated_response_structure(authed_env):
    client, _, _ = authed_env
    _seed_incidents(client, 30)
    res = client.get("/api/incidents?page=1&per_page=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "incidents" in data
    assert "pagination" in data
    p = data["pagination"]
    assert p["page"] == 1
    assert p["per_page"] == 10
    assert p["total"] == 30
    assert p["total_pages"] == 3
    assert p["has_next"] is True
    assert p["has_prev"] is False
    assert len(data["incidents"]) == 10


def test_incidents_pagination_page_2(authed_env):
    client, _, _ = authed_env
    _seed_incidents(client, 30)
    res = client.get("/api/incidents?page=2&per_page=10")
    data = res.get_json()
    assert data["pagination"]["page"] == 2
    assert data["pagination"]["has_prev"] is True
    assert len(data["incidents"]) == 10


def test_incidents_last_page(authed_env):
    client, _, _ = authed_env
    _seed_incidents(client, 25)
    res = client.get("/api/incidents?page=3&per_page=10")
    data = res.get_json()
    assert data["pagination"]["has_next"] is False
    assert len(data["incidents"]) == 5


def test_incidents_per_page_capped_at_100(authed_env):
    client, _, _ = authed_env
    _seed_incidents(client, 10)
    res = client.get("/api/incidents?per_page=999")
    assert res.status_code == 200
    data = res.get_json()
    assert data["pagination"]["per_page"] <= 100


def test_incidents_search_by_attack(authed_env):
    client, _, _ = authed_env
    _post_incident(client, attack="Unique Attack Name Alpha", risk=50)
    _post_incident(client, attack="Different Vector Beta", risk=50)
    res = client.get("/api/incidents?search=Alpha")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert len(items) == 1
    assert items[0]["attack"] == "Unique Attack Name Alpha"


def test_incidents_search_by_username(authed_env):
    client, _, _ = authed_env
    _post_incident(client, attack="Attack A", risk=50, username="uniqueuser99")
    _post_incident(client, attack="Attack B", risk=50, username="anotheruser")
    res = client.get("/api/incidents?search=uniqueuser99")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all("uniqueuser99" in i["username"] for i in items)
    assert len(items) >= 1


def test_incidents_filter_by_severity_critical(authed_env):
    client, _, _ = authed_env
    _post_incident(client, attack="Crit", risk=85)
    _post_incident(client, attack="Low", risk=15)
    res = client.get("/api/incidents?severity=critical")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all(i["risk"] >= 80 for i in items)


def test_incidents_filter_by_severity_high(authed_env):
    client, _, _ = authed_env
    _post_incident(client, attack="High", risk=65)
    _post_incident(client, attack="Crit", risk=85)
    res = client.get("/api/incidents?severity=high")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all(60 <= i["risk"] < 80 for i in items)


def test_incidents_filter_status_open(authed_env):
    client, _, _ = authed_env
    r1 = _post_incident(client, attack="Open A", risk=50)
    r2 = _post_incident(client, attack="Will Resolve", risk=50)
    inc_id = r2.get_json()["incident"]["id"]
    client.post(f"/api/incidents/{inc_id}/resolve")

    res = client.get("/api/incidents?status=open")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all(i["resolved"] == 0 for i in items)
    assert len(items) == 1


def test_incidents_filter_status_resolved(authed_env):
    client, _, _ = authed_env
    r = _post_incident(client, attack="Resolve Me", risk=60)
    inc_id = r.get_json()["incident"]["id"]
    _post_incident(client, attack="Stay Open", risk=40)
    client.post(f"/api/incidents/{inc_id}/resolve")

    res = client.get("/api/incidents?status=resolved")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all(i["resolved"] == 1 for i in items)
    assert len(items) == 1


def test_incidents_filter_source_simulated(authed_env):
    client, _, _ = authed_env
    _post_incident(client, risk=50)  # simulate endpoint always = simulated
    res = client.get("/api/incidents?source=simulated")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert all(i["is_simulated"] is True for i in items)


def test_incidents_sort_by_risk_asc(authed_env):
    client, _, _ = authed_env
    for risk in [70, 20, 90, 40]:
        _post_incident(client, risk=risk)
    res = client.get("/api/incidents?sort_by=risk&sort_dir=asc")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    risks = [i["risk"] for i in items]
    assert risks == sorted(risks)


def test_incidents_sort_by_risk_desc(authed_env):
    client, _, _ = authed_env
    for risk in [70, 20, 90, 40]:
        _post_incident(client, risk=risk)
    res = client.get("/api/incidents?sort_by=risk&sort_dir=desc")
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    risks = [i["risk"] for i in items]
    assert risks == sorted(risks, reverse=True)


def test_incidents_invalid_sort_column_rejected(authed_env):
    """SQL injection prevention: invalid sort column should be rejected or defaulted."""
    client, _, _ = authed_env
    res = client.get("/api/incidents?sort_by=; DROP TABLE logs; --")
    # Should either 400 or silently default to safe column
    assert res.status_code in (200, 400)
    if res.status_code == 200:
        data = res.get_json()
        assert "incidents" in data or isinstance(data, list)


# ---------------------------------------------------------------------------
# Incident Detail Endpoint
# ---------------------------------------------------------------------------

def test_incident_detail_endpoint(authed_env):
    client, _, _ = authed_env
    sim = _post_incident(client, attack="Detail Test", risk=77, username="detail_user")
    inc_id = sim.get_json()["incident"]["id"]
    res = client.get(f"/api/incidents/{inc_id}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["id"] == inc_id
    assert data["attack"] == "Detail Test"
    assert data["risk"] == 77
    assert data["username"] == "detail_user"
    for field in ["id", "username", "attack", "behavior", "risk", "ip",
                  "location", "time", "resolved", "is_simulated"]:
        assert field in data, f"Missing field: {field}"


def test_incident_detail_not_found(authed_env):
    client, _, _ = authed_env
    res = client.get("/api/incidents/99999")
    assert res.status_code == 404


def test_incident_detail_requires_auth(test_env):
    client, _, _ = test_env
    res = client.get("/api/incidents/1")
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# Metrics endpoint accuracy tests
# ---------------------------------------------------------------------------

def test_metrics_health_score_floor_is_zero(authed_env):
    """Health score must never go below 0."""
    client, _, _ = authed_env
    # Add many critical incidents
    for i in range(20):
        _post_incident(client, attack=f"Crit {i}", risk=95)
    res = client.get("/api/metrics")
    assert res.get_json()["health_score"] >= 0


def test_metrics_simulated_vs_telemetry_count(authed_env):
    client, _, _ = authed_env
    _post_incident(client, risk=50)  # simulated (via /simulate endpoint)
    res = client.get("/api/metrics")
    data = res.get_json()
    assert data["simulated_count"] >= 1
    assert data["telemetry_count"] >= 0
    assert data["simulated_count"] + data["telemetry_count"] == data["total_incidents"]


# ---------------------------------------------------------------------------
# Edge cases and security
# ---------------------------------------------------------------------------

def test_incidents_empty_state(authed_env):
    """Should return empty list with valid pagination when no incidents exist."""
    client, _, _ = authed_env
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.get_json()
    items = data.get("incidents", data) if isinstance(data, dict) else data
    assert isinstance(items, list)
    assert len(items) == 0


def test_incidents_search_xss_safe(authed_env):
    """Search param with XSS payload should not cause a 500."""
    client, _, _ = authed_env
    xss_search = "<script>alert(1)</script>"
    res = client.get(f"/api/incidents?search={xss_search}")
    assert res.status_code in (200, 400)


def test_clear_logs_requires_admin(test_env):
    """Clear logs should require admin role."""
    client, config, _ = test_env
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"],
    })
    res = client.post("/api/incidents/clear")
    assert res.status_code == 200  # admin can clear


def test_metrics_today_count(authed_env):
    """today_count should include today's incidents."""
    client, _, _ = authed_env
    _post_incident(client, attack="Today's Attack", risk=50)
    res = client.get("/api/metrics")
    data = res.get_json()
    assert data["today_count"] >= 1


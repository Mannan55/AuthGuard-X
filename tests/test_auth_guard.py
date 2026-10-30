import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add backend directory to path
BASE_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BASE_DIR))

from app import create_app, get_db_connection, is_private_or_loopback_ip, resolve_ip_location


@pytest.fixture
def test_env(tmp_path):
    """Fixture providing an isolated SQLite database and test Flask client."""
    db_file = tmp_path / "test_authguard.db"
    config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "development",
        "DEMO_MODE": True,
        "SEED_DEMO_USER": True,
        "DEMO_ADMIN_USER": "testadmin",
        "DEMO_ADMIN_PASSWORD": "TestPassword123!",
        "SECRET_KEY": "test-secret-key-for-authguard-x",
        "ENABLE_EXTERNAL_GEOIP": False
    }

    app = create_app(test_config=config)
    with app.test_client() as client:
        yield client, config, str(db_file)


# -----------------------------------------------------------------------------
# 1. Health & Configuration Tests
# -----------------------------------------------------------------------------
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
    assert b"SOC" in res.data


# -----------------------------------------------------------------------------
# 2. Authentication Tests (Valid, Invalid, Session)
# -----------------------------------------------------------------------------
def test_login_valid(test_env):
    client, config, _ = test_env
    res = client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
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
        "password": "WrongPassword999!"
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data["status"] == "fail"


def test_login_missing_fields(test_env):
    client, _, _ = test_env
    res = client.post("/api/auth/login", json={"username": "admin"})
    assert res.status_code == 400
    data = res.get_json()
    assert data["status"] == "fail"


# -----------------------------------------------------------------------------
# 3. Access Control Without Authentication
# -----------------------------------------------------------------------------
def test_access_without_auth_blocked(test_env):
    client, _, _ = test_env

    # Attempt to retrieve logs without session
    res_logs = client.get("/api/incidents")
    assert res_logs.status_code == 401
    assert "Unauthorized" in res_logs.get_json()["error"]

    # Attempt to simulate attack without session
    res_sim = client.post("/api/incidents/simulate", json={
        "attack": "Brute Force",
        "risk": 80
    })
    assert res_sim.status_code == 401

    # Attempt to resolve incident without session
    res_resolve = client.post("/api/incidents/1/resolve")
    assert res_resolve.status_code == 401


# -----------------------------------------------------------------------------
# 4. Session Expiration & Logout
# -----------------------------------------------------------------------------
def test_session_status_and_logout(test_env):
    client, config, _ = test_env

    # Initially unauthenticated
    res_before = client.get("/api/auth/session")
    assert res_before.status_code == 200
    assert res_before.get_json()["authenticated"] is False

    # Login
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })

    # Now authenticated
    res_after = client.get("/api/auth/session")
    assert res_after.status_code == 200
    assert res_after.get_json()["authenticated"] is True
    assert res_after.get_json()["user"]["username"] == config["DEMO_ADMIN_USER"]

    # Logout
    res_logout = client.post("/api/auth/logout")
    assert res_logout.status_code == 200
    assert res_logout.get_json()["status"] == "success"

    # Status check confirms session invalidated
    res_post_logout = client.get("/api/auth/session")
    assert res_post_logout.get_json()["authenticated"] is False


# -----------------------------------------------------------------------------
# 5. Attack Simulation & Incident Logging
# -----------------------------------------------------------------------------
def test_attack_simulation_and_incident_logging(test_env):
    client, config, _ = test_env

    # Authenticate
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })

    # Simulate attack
    sim_payload = {
        "attack": "Credential Stuffing",
        "risk": 75,
        "behavior": "automated_proxy",
        "username": "victim_account",
        "is_simulated": True,
        "simulated_location": "Frankfurt, Germany"
    }
    res = client.post("/api/incidents/simulate", json=sim_payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["incident"]["attack"] == "Credential Stuffing"
    assert data["incident"]["risk"] == 75
    assert data["incident"]["is_simulated"] is True
    assert "Simulated" in data["incident"]["location"]

    # Verify log appears in incident list
    res_list = client.get("/api/incidents")
    assert res_list.status_code == 200
    incidents = res_list.get_json()
    assert len(incidents) == 1
    assert incidents[0]["attack"] == "Credential Stuffing"
    assert incidents[0]["is_simulated"] is True


# -----------------------------------------------------------------------------
# 6. Authorized vs Unauthorized Incident Resolution
# -----------------------------------------------------------------------------
def test_incident_resolution(test_env):
    client, config, _ = test_env

    # Login and create an incident
    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })
    sim_res = client.post("/api/incidents/simulate", json={
        "attack": "SQL Injection Attempt",
        "risk": 90
    })
    inc_id = sim_res.get_json()["incident"]["id"]

    # Move incident to investigating
    client.patch(f"/api/incidents/{inc_id}/case", json={"status": "investigating", "version": 1})

    # Resolve incident with required resolution summary
    res_resolve = client.post(f"/api/incidents/{inc_id}/resolve", json={"summary": "Remediated SQL injection threat"})
    assert res_resolve.status_code == 200
    assert res_resolve.get_json()["status"] == "success"

    # Confirm incident is resolved in incident list
    res_list = client.get("/api/incidents")
    assert res_list.get_json()[0]["resolved"] == 1

    # Attempt to resolve non-existent incident
    res_not_found = client.post("/api/incidents/9999/resolve")
    assert res_not_found.status_code == 404


# -----------------------------------------------------------------------------
# 7. Backward Compatibility with Legacy Endpoints
# -----------------------------------------------------------------------------
def test_legacy_endpoint_aliases(test_env):
    client, config, _ = test_env

    # Legacy login at /login
    login_res = client.post("/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })
    assert login_res.status_code == 200

    # Legacy attack logging at /log_attack
    log_res = client.post("/log_attack", json={
        "username": "legacy_user",
        "attack": "Port Scan",
        "behavior": "recon",
        "risk": 45
    })
    assert log_res.status_code == 201
    log_id = log_res.get_json()["incident"]["id"]

    # Legacy log retrieval at /get_logs
    get_res = client.get("/get_logs")
    assert get_res.status_code == 200
    logs = get_res.get_json()
    assert len(logs) == 1
    assert logs[0]["attack"] == "Port Scan"

    # Legacy resolve at /resolve_incident/<id>
    client.patch(f"/api/incidents/{log_id}/case", json={"status": "investigating", "version": 1})
    resolve_res = client.post(f"/resolve_incident/{log_id}", json={"summary": "Remediated port scan activity"})
    assert resolve_res.status_code == 200

    # Legacy logout at /logout
    logout_res = client.post("/logout")
    assert logout_res.status_code == 200


# -----------------------------------------------------------------------------
# 8. Input Validation & Boundaries
# -----------------------------------------------------------------------------
def test_input_validation(test_env):
    client, config, _ = test_env

    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })

    # Negative risk score
    res_neg = client.post("/api/incidents/simulate", json={"attack": "Test", "risk": -10})
    assert res_neg.status_code == 400

    # Risk score > 100
    res_high = client.post("/api/incidents/simulate", json={"attack": "Test", "risk": 150})
    assert res_high.status_code == 400

    # Non-integer risk score
    res_str = client.post("/api/incidents/simulate", json={"attack": "Test", "risk": "critical"})
    assert res_str.status_code == 400

    # Missing attack field
    res_missing = client.post("/api/incidents/simulate", json={"risk": 50})
    assert res_missing.status_code == 400


# -----------------------------------------------------------------------------
# 9. XSS Resistance & Safe Data Handling
# -----------------------------------------------------------------------------
def test_xss_resistance(test_env):
    client, config, _ = test_env

    client.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })

    # Attempt to inject XSS scripts via incident attack and username
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    res = client.post("/api/incidents/simulate", json={
        "attack": xss_payload,
        "username": xss_payload,
        "risk": 50
    })
    assert res.status_code == 201

    # Verify that the returned JSON retains the literal string as data
    res_logs = client.get("/api/incidents")
    entry = res_logs.get_json()[0]
    assert entry["attack"] == xss_payload
    assert entry["username"] == xss_payload


# -----------------------------------------------------------------------------
# 10. Database Persistence After Restart
# -----------------------------------------------------------------------------
def test_database_persistence_across_restarts(test_env):
    client1, config, db_path = test_env

    # App session 1: create incident
    client1.post("/api/auth/login", json={
        "username": config["DEMO_ADMIN_USER"],
        "password": config["DEMO_ADMIN_PASSWORD"]
    })
    client1.post("/api/incidents/simulate", json={
        "attack": "Persistent Attack Vector",
        "risk": 99,
        "username": "target_corp"
    })

    # Simulate server shutdown and new instance launch with the same database
    new_app = create_app(test_config=config)
    with new_app.test_client() as client2:
        # Log into new instance
        client2.post("/api/auth/login", json={
            "username": config["DEMO_ADMIN_USER"],
            "password": config["DEMO_ADMIN_PASSWORD"]
        })
        res = client2.get("/api/incidents")
        assert res.status_code == 200
        logs = res.get_json()
        assert len(logs) == 1
        assert logs[0]["attack"] == "Persistent Attack Vector"
        assert logs[0]["risk"] == 99


# -----------------------------------------------------------------------------
# 11. Production Mode Protection & Offline IP Resolution
# -----------------------------------------------------------------------------
def test_production_mode_disables_demo_user(tmp_path):
    db_file = tmp_path / "prod_authguard.db"
    prod_config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "AUTHGUARD_ENV": "production",
        "DEMO_MODE": False,
        "SEED_DEMO_USER": True,  # should be ignored in production
        "DEMO_ADMIN_USER": "prod_demo",
        "DEMO_ADMIN_PASSWORD": "ShouldNotBeCreated!",
        "SECRET_KEY": "a-very-secure-64-character-production-secret-key-1234567890abcdef"
    }

    prod_app = create_app(test_config=prod_config)
    with prod_app.test_client() as client:
        # Verify demo user was NOT created
        login_res = client.post("/api/auth/login", json={
            "username": "prod_demo",
            "password": "ShouldNotBeCreated!"
        })
        assert login_res.status_code == 401

        # Verify demo credentials are NOT revealed in session status
        status_res = client.get("/api/auth/session")
        assert status_res.get_json().get("demo_credentials") is None


def test_ip_helpers():
    assert is_private_or_loopback_ip("127.0.0.1") is True
    assert is_private_or_loopback_ip("::1") is True
    assert is_private_or_loopback_ip("192.168.1.100") is True
    assert is_private_or_loopback_ip("10.0.0.5") is True
    assert is_private_or_loopback_ip("8.8.8.8") is False

    # Loopback IP should resolve locally without network calls
    loc = resolve_ip_location("127.0.0.1", enable_external_geoip=False)
    assert "Internal" in loc

# AuthGuard-X — Security Operations Center (SOC) Simulation & Hardening Platform

[![CI / Security & Quality Verification](https://github.com/Mannan55/AuthGuard-X/actions/workflows/ci.yml/badge.svg)](https://github.com/Mannan55/AuthGuard-X/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/backend-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AuthGuard-X is a professional Security Operations Center (SOC) demonstration, training, and incident investigation platform designed for cybersecurity analysts, educators, and incident response teams. It models an identity security monitoring system that detects, visualizes, investigates, and remediates suspicious authentication telemetry, credential attacks, and anomalous behavior.

> **Simulation & Telemetry Provenance Disclosure:** All attack vectors, simulated incident streams, and geographic origins are generated locally for training and demonstration purposes with server-enforced provenance (`is_simulated = 1`). AuthGuard-X does not execute live exploits or claim unverified external threat feeds.

---

## Visual Demonstration & SOC Workspace (Sprint 2)

| 1. Authentication Portal | 2. Operational SOC Overview |
|:---:|:---:|
| ![Login View](docs/screenshots/01_login_view.png) | ![Dashboard Overview](docs/screenshots/02_dashboard_overview.png) |
| *Session-based login with dev credential guidance* | *Live KPI cards, dynamic health score & threat timeline* |

| 3. Advanced Incident Management Table | 4. Incident Detail Triage Modal |
|:---:|:---:|
| ![Incidents Table](docs/screenshots/03_incidents_table.png) | ![Incident Detail](docs/screenshots/04_incident_detail_modal.png) |
| *Search by ID/text, severity/status/source filters & pagination* | *Audit metadata, one-click remediation & investigation routing* |

| 5. Attack Simulation Lab | 6. Analyst Incident Work Queue |
|:---:|:---:|
| ![Simulations View](docs/screenshots/06_simulations_lab_view.png) | ![Case Queue View](docs/screenshots/07_case_queue_view.png) |
| *Controlled synthetic vector injection with city/risk targeting* | *Queue isolation, active triage filters & real-time KPI metrics* |

| 7. Investigation Workspace & Lifecycle Stepper | 8. Evidence Metadata & Audit Timeline |
|:---:|:---:|
| ![Investigation Workspace](docs/screenshots/08_investigation_workspace.png) | ![Timeline & Evidence](docs/screenshots/09_investigation_timeline_and_evidence.png) |
| *State machine progression (`New` → `Investigating` → `Contained` → `Resolved`)* | *Sanitized notes, IOC/pcap evidence pointers & tamper-evident audit history* |

<div align="center">
  <img src="docs/screenshots/10_mobile_investigation_view.png" width="360" alt="Mobile Responsive Investigation Layout" />
  <p><em>Responsive mobile analyst investigation layout with zero horizontal overflow</em></p>
</div>

---

## Cybersecurity & SOC Use Cases

1. **Structured Case Investigation Training**: Transition junior and tier-2 analysts from basic alert closing to a rigorous 4-stage lifecycle state machine (**New → Investigating → Contained → Resolved**).
2. **Analyst Ownership & Queue Triage**: Model multi-analyst SOC shift workflows where analysts claim unassigned incidents, manage personal active queues, and collaborate with role-based isolation.
3. **Forensic Findings & Evidence Collection**: Capture timestamped triage observations, hypothesis testing notes, and attach structured evidence pointers (IOC hashes, network PCAP references, log excerpts) with URL scheme safety validation.
4. **Accountability & Tamper-Evident Auditing**: Maintain an append-only audit trail logging every state transition, analyst reassignment, and containment timestamp with server-derived actor identity.
5. **Attack Vector Simulation Engine**: Generate synthetic credential-stuffing, lateral traversal, and Kerberoasting telemetry to evaluate detection posture and test analyst workflows.
6. **Defensive Hardening Reference**: Production-grade Flask architecture featuring bcrypt password hashing (12 rounds), signed session cookies, CSRF protection, RBAC middleware, and XSS sanitization.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Web Browser (Frontend)         |
                      |  - Modular Vanilla JS (ES6+)          |
                      |  - Design Tokens & 8px Spacing Grid   |
                      |  - Investigation Lifecycle Stepper    |
                      |  - Real-time Work Queue & Metrics     |
                      |  - XSS-Safe DOM Sanitization          |
                      +-------------------+-------------------+
                                          |
                        HTTP / JSON (REST)| Session Cookies + CSRF Token
                        SameSite=Lax      | HttpOnly + X-CSRFToken
                                          v
                      +-------------------+-------------------+
                      |      Flask Application Server         |
                      |  - Session Auth & RBAC Middleware     |
                      |  - Lifecycle State Machine Engine     |
                      |  - Flask-WTF CSRF Token Enforcement   |
                      |  - Rate Limiting (Flask-Limiter)      |
                      |  - Search, Filter, Sort, Pagination   |
                      |  - Evidence Reference URL Validation  |
                      |  - Transactional Audit Logger         |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |       Persistence Engine (SQLite)     |
                      |  - `users`: bcrypt hashed credentials |
                      |  - `logs`: Incident telemetry records |
                      |  - `cases`: Lifecycle status & owners |
                      |  - `incident_notes`: Forensic notes   |
                      |  - `incident_evidence`: Metadata/IOCs |
                      |  - `incident_audit_log`: Audit trail  |
                      +---------------------------------------+
```

---

## Investigation Lifecycle State Machine

AuthGuard-X implements an enterprise SOC incident response lifecycle:

```
    [ New ] --------( Start Investigation / Claim )--------> [ Investigating ]
                                                                   |
                                                                   | ( Mark Contained )
                                                                   v
    [ Resolved ] <-------( Resolve + Document Summary )------ [ Contained ]
         |
         +----------( Reopen + Mandatory Justification )-----> [ Investigating ]
```

### State Machine Rules:
- **New → Investigating**: Permitted for assigned analyst or when claiming unassigned incident. Sets `investigation_started_at`.
- **Investigating → Contained**: Indicates isolation of affected host, credential rotation, or firewall block. Sets `contained_at`.
- **Contained → Resolved**: Requires a mandatory, non-trivial resolution summary (minimum 5 characters) explaining root cause and remediation. Sets `resolved_at` and synchronizes legacy `logs.resolved = 1`.
- **Investigating → Resolved**: Direct resolution permitted with mandatory resolution summary.
- **Resolved → Investigating (Reopening)**: Requires mandatory justification. Resets `logs.resolved = 0` and increments `reopen_count`.
- **Invalid Transitions**: Any backward jump without reopening (e.g., `Resolved → Contained`, `Contained → New`) is strictly rejected with `400 Bad Request`.

---

## Role-Based Access Control (RBAC) Matrix

| Endpoint / Operation | Analyst | Administrator | Unauthenticated |
|---|:---:|:---:|:---:|
| `GET /api/incidents` (Search/Filter/List) | Allowed | Allowed | 401 Unauthorized |
| `GET /api/incidents/<id>/case` (Details) | Allowed | Allowed | 401 Unauthorized |
| `PATCH /api/incidents/<id>/case` (Lifecycle) | Assigned / Claimed Only | Allowed Any | 401 Unauthorized |
| `POST /api/incidents/<id>/assign` (Self-Claim) | Unassigned Only | Allowed Any | 401 Unauthorized |
| `POST /api/incidents/<id>/assign` (Reassign Others) | 403 Forbidden | Allowed | 401 Unauthorized |
| `POST /api/incidents/<id>/notes` (Add Note) | Allowed | Allowed | 401 Unauthorized |
| `POST /api/incidents/<id>/evidence` (Add IOC) | Allowed | Allowed | 401 Unauthorized |
| `GET /api/cases/my-queue` (Personal Queue) | Personal Cases | Personal Cases | 401 Unauthorized |
| `GET /api/cases/unassigned` (Unclaimed) | Allowed | Allowed | 401 Unauthorized |
| `POST /api/incidents/clear` (Purge Protection) | 403 Forbidden | Requires Confirmation / Force Purge | 401 Unauthorized |
| `POST /api/users/create` (Create Analyst) | 403 Forbidden | Allowed | 401 Unauthorized |

---

## Technology Stack

- **Backend Framework**: Python 3.11+ / Flask 3.1
- **Security & Cryptography**: `bcrypt` (adaptive blowfish hashing, 12 rounds), `secrets` (CSPRNG session keys)
- **CSRF & Form Defense**: `Flask-WTF` CSRF protection with `/api/auth/csrf-token` endpoint
- **Session & Origin Management**: Flask Session (`HttpOnly`, `SameSite=Lax`, `Secure` in production), `Flask-Cors` (strict whitelist)
- **Traffic Protection**: `Flask-Limiter` (IP-based endpoint rate throttling)
- **Frontend Architecture**: Modular Vanilla JavaScript (ES6+), design tokens (`tokens.css`), responsive layout (`layout.css`), accessible components (`components.css`), Chart.js
- **Database Engine**: SQLite3 with strict foreign keys (`PRAGMA foreign_keys = ON`), indexed lookups, and idempotent migrations
- **Automated QA**: Pytest suite (88 tests) and headless Chrome CDP browser automation (15 real assertions)

---

## Quickstart & Execution Guide

### Prerequisites
- Python 3.11 or later installed.
- Git.

### 1. Clone & Set Up Environment

```powershell
# Clone the repository
git clone https://github.com/Mannan55/AuthGuard-X.git
cd AuthGuard-X

# Create and activate a virtual environment (optional but recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1    # On Windows
# source venv/bin/activate     # On Linux / macOS

# Install dependencies
pip install -r backend/requirements.txt
```

### 2. Configure Environment Variables

```powershell
# Copy the provided environment template
cp .env.example .env    # On Linux / macOS
copy .env.example .env  # On Windows
```

Key environment configuration variables:

```ini
AUTHGUARD_ENV=development
HOST=127.0.0.1
PORT=5000
SECRET_KEY=your-cryptographic-secret-key-32bytes
DEMO_MODE=true
SEED_DEMO_USER=true
DEMO_ADMIN_USER=admin
DEMO_ADMIN_PASSWORD=DemoAdminPassword2026!
CORS_ALLOWED_ORIGINS=http://127.0.0.1:5000,http://localhost:5000
ENABLE_EXTERNAL_GEOIP=false
```

### 3. Run the Application

```powershell
python backend/app.py
```

Open your browser to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

Default development accounts:
- **Administrator**: `admin` / `DemoAdminPassword2026!`
- **Tier-1 Analyst**: `analyst_john` / `AnalystJohn2026!`
- **Tier-2 Analyst**: `analyst_jane` / `AnalystJane2026!`

---

## Automated Verification & Testing

The project includes two comprehensive layers of automated verification:

```powershell
# 1. Run the complete Pytest suite (88 tests)
pytest tests -v

# 2. Run real-browser visual and functional verification (15 assertions + screenshots)
python scripts/capture_evidence.py
```

### Test Suite Distribution (88 Tests Total)
- **Phase 1 Baseline** (`tests/test_auth_guard.py` — 15 tests): Health check, login validation, session state, unauthenticated access blocking, and persistence across restarts.
- **Sprint 1 Professional UI & Hardening** (`tests/test_sprint1.py` — 54 tests): CSRF validation, simulation provenance enforcement, server-derived metrics, pagination envelopes, search/filter/sort allowlists, detail endpoints, and XSS resistance.
- **Sprint 2 Advanced SOC Investigation** (`tests/test_sprint2.py` — 19 tests): Idempotent database migrations, automatic case creation, 4-stage lifecycle state machine, reopening workflow, mandatory resolution summary, analyst claiming/assignment RBAC, persistent investigation notes, evidence metadata validation, administrative log purge protection, personal queue isolation, and CSRF enforcement on case APIs.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

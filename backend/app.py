import os
import sys
import math
import secrets
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import bcrypt
from dotenv import load_dotenv

# Load environment configuration from .env in backend directory or root
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

if (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env")
elif (ROOT_DIR / ".env").exists():
    load_dotenv(ROOT_DIR / ".env")
else:
    load_dotenv()


def resolve_db_path(db_setting: str) -> str:
    path = Path(db_setting)
    if not path.is_absolute():
        return str(BASE_DIR / path)
    return str(path)


def get_db_connection(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str, app_env: str, demo_mode: bool, seed_demo: bool,
            demo_user: str, demo_pass: str):
    """
    Initializes database tables and safely migrates schema if needed.
    Demo user and development analysts are explicitly seeded ONLY in development environment when enabled.
    """
    conn = get_db_connection(db_path)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        )
    ''')

    # Incidents / attack logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            attack TEXT NOT NULL,
            behavior TEXT NOT NULL,
            risk INTEGER NOT NULL,
            ip TEXT NOT NULL,
            location TEXT NOT NULL,
            time TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            is_simulated INTEGER DEFAULT 0
        )
    ''')

    # Safe migration: ensure is_simulated column exists in logs
    c.execute("PRAGMA table_info(logs)")
    columns = [row["name"] for row in c.fetchall()]
    if "is_simulated" not in columns:
        c.execute("ALTER TABLE logs ADD COLUMN is_simulated INTEGER DEFAULT 0")

    # Sprint 2: Cases table (Lifecycle: new -> investigating -> contained -> resolved)
    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            incident_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'investigating', 'contained', 'resolved')),
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

    # Safe migration: ensure reopen_count and version columns exist in cases
    c.execute("PRAGMA table_info(cases)")
    case_cols = [row["name"] for row in c.fetchall()]
    if "reopen_count" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN reopen_count INTEGER NOT NULL DEFAULT 0")
    if "version" not in case_cols:
        c.execute("ALTER TABLE cases ADD COLUMN version INTEGER NOT NULL DEFAULT 1")

    # Sprint 2: Investigation notes table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            author_username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: Evidence reference metadata table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            description TEXT NOT NULL,
            added_by_id INTEGER NOT NULL,
            added_by_username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: Append-only incident activity audit trail table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incident_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            actor_id INTEGER NOT NULL,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            before_value TEXT,
            after_value TEXT,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES logs(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Sprint 2: System-level administrative audit log (retained even after incident purge)
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            actor_username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            reason TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    ''')

    # Sprint 2: Performance indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cases_assigned_to ON cases(assigned_to)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_incident ON incident_audit_log(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_system_audit_action ON system_audit_log(action)")

    # Idempotent Backfill: Create case records for existing logs that don't have one.
    # CRITICAL: Preserve unknown historical resolution times as NULL (do not overwrite with creation time).
    c.execute('''
        INSERT INTO cases (incident_id, status, created_at, updated_at, resolved_at, resolution_summary, reopen_count, version)
        SELECT 
            id,
            CASE WHEN resolved = 1 THEN 'resolved' ELSE 'new' END,
            time,
            time,
            NULL,
            CASE WHEN resolved = 1 THEN 'Historical incident from prior system version' ELSE NULL END,
            0,
            1
        FROM logs
        WHERE id NOT IN (SELECT incident_id FROM cases)
    ''')

    # Safe demo user provisioning
    # Strictly prohibited in production!
    if app_env == "development" and demo_mode and seed_demo:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Admin user
        c.execute("SELECT id FROM users WHERE username = ?", (demo_user,))
        existing_admin = c.fetchone()
        if not existing_admin and demo_user and demo_pass:
            pw_hash = bcrypt.hashpw(demo_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
            c.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (demo_user, pw_hash, "admin", now)
            )
            print(f"[AUTHGUARD-INIT] Development demo user provisioned: '{demo_user}'")

        # Development analyst users for assignment workflow demonstrations
        demo_analysts = [
            ("analyst_john", "AnalystJohn2026!", "analyst"),
            ("analyst_jane", "AnalystJane2026!", "analyst"),
        ]
        for a_user, a_pass, a_role in demo_analysts:
            c.execute("SELECT id FROM users WHERE username = ?", (a_user,))
            if not c.fetchone():
                a_hash = bcrypt.hashpw(a_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
                c.execute(
                    "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                    (a_user, a_hash, a_role, now)
                )
                print(f"[AUTHGUARD-INIT] Development analyst provisioned: '{a_user}'")

    conn.commit()
    conn.close()


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Checks whether an IP address is loopback, private, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def resolve_ip_location(ip_str: str, enable_external_geoip: bool = False) -> str:
    """
    Safely resolves location without unencrypted HTTP leakage.
    Loopback/internal IPs are resolved offline immediately.
    External geolocation is disabled by default to prevent privacy leaks.
    """
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
        return "Internal / Localhost"

    if is_private_or_loopback_ip(ip_str):
        return "Internal Network (RFC 1918 / Private)"

    if not enable_external_geoip:
        return "External Network (Offline GeoIP)"

    # Optional HTTPS geolocation (only if explicitly enabled)
    try:
        import requests
        # Always use HTTPS
        resp = requests.get(f"https://ipapi.co/{ip_str}/json/", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            city = data.get("city", "")
            country = data.get("country_name", "")
            if city or country:
                return f"{city}, {country}".strip(", ")
    except Exception:
        pass

    return "External Location"


# ---------------------------------------------------------------------------
# Allowlisted sort columns for /api/incidents to prevent SQL injection
# ---------------------------------------------------------------------------
_INCIDENTS_SORT_ALLOWLIST = {
    "id": "logs.id",
    "risk": "logs.risk",
    "time": "logs.time",
    "username": "logs.username",
    "attack": "logs.attack",
    "status": "cases.status",
    "assigned_username": "cases.assigned_username",
}


def _build_incidents_query(
    search=None,
    severity=None,
    status="all",
    source="all",
    sort_by="id",
    sort_dir="desc",
    page=None,
    per_page=25,
    date_from=None,
    date_to=None,
    assigned_to=None,
):
    """
    Constructs a parameterized SQL query for the incidents/logs table with cases join.

    All user-supplied filter values are bound via parameters (never interpolated).
    The sort column is validated against an explicit allowlist before insertion.

    Returns (count_sql, data_sql, params, limit, offset) where limit/offset are
    None when pagination is not requested (page=None).
    """
    conditions = []
    params = []

    # --- Search filter (ID exact/substring & text LIKE, parameterized) ---
    if search:
        raw_search = str(search).strip()
        term = f"%{raw_search}%"
        stripped_id = raw_search.lstrip("#").strip()
        if stripped_id.isdigit():
            # Exact numeric ID or substring match, plus text fields
            exact_id = int(stripped_id)
            conditions.append(
                "(logs.id = ? OR CAST(logs.id AS TEXT) LIKE ? OR logs.username LIKE ? OR logs.attack LIKE ? OR logs.behavior LIKE ? OR cases.assigned_username LIKE ?)"
            )
            params.extend([exact_id, f"%{stripped_id}%", term, term, term, term])
        else:
            conditions.append(
                "(CAST(logs.id AS TEXT) LIKE ? OR logs.username LIKE ? OR logs.attack LIKE ? OR logs.behavior LIKE ? OR cases.assigned_username LIKE ?)"
            )
            params.extend([term, term, term, term, term])

    # --- Severity filter (maps to risk score ranges) ---
    if severity:
        severity = severity.lower()
        if severity == "critical":
            conditions.append("logs.risk >= ?")
            params.append(80)
        elif severity == "high":
            conditions.append("logs.risk >= ? AND logs.risk < ?")
            params.extend([60, 80])
        elif severity == "medium":
            conditions.append("logs.risk >= ? AND logs.risk < ?")
            params.extend([40, 60])
        elif severity == "low":
            conditions.append("logs.risk < ?")
            params.append(40)

    # --- Status filter ---
    if status and status != "all":
        st = status.lower()
        if st == "open":
            conditions.append("logs.resolved = ?")
            params.append(0)
        elif st == "resolved":
            conditions.append("logs.resolved = ?")
            params.append(1)
        elif st in ("new", "investigating", "contained"):
            conditions.append("cases.status = ?")
            params.append(st)

    # --- Source filter ---
    if source and source != "all":
        if source == "simulated":
            conditions.append("logs.is_simulated = ?")
            params.append(1)
        elif source == "telemetry":
            conditions.append("logs.is_simulated = ?")
            params.append(0)

    # --- Assigned To filter ---
    if assigned_to is not None:
        if str(assigned_to).lower() == "unassigned":
            conditions.append("cases.assigned_to IS NULL")
        else:
            try:
                uid = int(assigned_to)
                conditions.append("cases.assigned_to = ?")
                params.append(uid)
            except (ValueError, TypeError):
                pass

    # --- Date range filter ---
    if date_from:
        try:
            datetime.strptime(date_from, "%Y-%m-%d")
            conditions.append("logs.time >= ?")
            params.append(f"{date_from} 00:00:00")
        except ValueError:
            pass  # Ignore malformed dates silently

    if date_to:
        try:
            datetime.strptime(date_to, "%Y-%m-%d")
            conditions.append("logs.time <= ?")
            params.append(f"{date_to} 23:59:59")
        except ValueError:
            pass

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # --- Sort column allowlist enforcement (prevents ORDER BY injection) ---
    col_order = _INCIDENTS_SORT_ALLOWLIST.get(sort_by, "logs.id")
    sort_dir = "ASC" if str(sort_dir).lower() == "asc" else "DESC"

    base_select = f"""
        SELECT 
            logs.id, logs.username, logs.attack, logs.behavior, logs.risk, logs.ip, logs.location, logs.time, logs.resolved, logs.is_simulated,
            cases.status, cases.assigned_to, cases.assigned_username, cases.assigned_at,
            cases.investigation_started_at, cases.contained_at, cases.resolved_at, cases.resolution_summary,
            cases.reopen_count, cases.version, cases.updated_at
        FROM logs
        LEFT JOIN cases ON logs.id = cases.incident_id
        {where_clause}
        ORDER BY {col_order} {sort_dir}
    """

    count_select = f"""
        SELECT COUNT(*) AS total 
        FROM logs 
        LEFT JOIN cases ON logs.id = cases.incident_id 
        {where_clause}
    """

    return count_select, base_select, params


def _row_to_dict(r):
    """Converts a sqlite3.Row from the logs table (with joined case data) to a plain dict."""
    keys = r.keys()
    is_sim = bool(r["is_simulated"]) if ("is_simulated" in keys and r["is_simulated"] is not None) else False
    status_val = r["status"] if ("status" in keys and r["status"]) else None
    if not status_val:
        status_val = "resolved" if r["resolved"] == 1 else "new"

    return {
        "id": r["id"],
        "username": r["username"],
        "attack": r["attack"],
        "behavior": r["behavior"],
        "risk": r["risk"],
        "ip": r["ip"],
        "location": r["location"],
        "time": r["time"],
        "resolved": r["resolved"],
        "is_simulated": is_sim,
        "status": status_val,
        "assigned_to": r["assigned_to"] if ("assigned_to" in keys and r["assigned_to"] is not None and r["assigned_to"] != "") else None,
        "assigned_username": r["assigned_username"] if ("assigned_username" in keys and r["assigned_username"]) else None,
        "assigned_at": r["assigned_at"] if ("assigned_at" in keys and r["assigned_at"]) else None,
        "investigation_started_at": r["investigation_started_at"] if ("investigation_started_at" in keys and r["investigation_started_at"]) else None,
        "contained_at": r["contained_at"] if ("contained_at" in keys and r["contained_at"]) else None,
        "resolved_at": r["resolved_at"] if ("resolved_at" in keys and r["resolved_at"]) else None,
        "resolution_summary": r["resolution_summary"] if ("resolution_summary" in keys and r["resolution_summary"]) else None,
        "reopen_count": r["reopen_count"] if ("reopen_count" in keys and r["reopen_count"] is not None) else 0,
        "version": r["version"] if ("version" in keys and r["version"] is not None) else 1,
        "updated_at": r["updated_at"] if ("updated_at" in keys and r["updated_at"]) else None,
    }


def create_app(test_config=None) -> Flask:
    app = Flask(__name__, static_folder="../frontend", static_url_path="")

    # Load configuration
    app_env = os.getenv("AUTHGUARD_ENV", "development").lower()
    demo_mode = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    seed_demo = os.getenv("SEED_DEMO_USER", "true").lower() in ("true", "1", "yes")
    demo_user = os.getenv("DEMO_ADMIN_USER", "admin")
    demo_pass = os.getenv("DEMO_ADMIN_PASSWORD", "DemoAdmin2026!")

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        if app_env == "production":
            raise RuntimeError("CRITICAL: SECRET_KEY must be explicitly configured in production!")
        secret_key = secrets.token_hex(32)

    db_path_env = os.getenv("DATABASE_PATH", "authguard.db")
    db_path = resolve_db_path(db_path_env)
    enable_external_geoip = os.getenv("ENABLE_EXTERNAL_GEOIP", "false").lower() in ("true", "1", "yes")
    cors_allowed = os.getenv("CORS_ALLOWED_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000").split(",")
    cors_allowed = [origin.strip() for origin in cors_allowed if origin.strip()]

    # Flask application settings
    app.config.update(
        SECRET_KEY=secret_key,
        AUTHGUARD_ENV=app_env,
        DEMO_MODE=demo_mode,
        SEED_DEMO_USER=seed_demo,
        DEMO_ADMIN_USER=demo_user,
        DEMO_ADMIN_PASSWORD=demo_pass,
        DATABASE_PATH=db_path,
        ENABLE_EXTERNAL_GEOIP=enable_external_geoip,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(app_env == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        # CSRF is enabled by default; disabled in TESTING mode so existing
        # tests (which do not supply CSRF tokens) continue to pass.
        WTF_CSRF_ENABLED=True,
    )

    if test_config:
        app.config.update(test_config)

    # Automatically disable CSRF when running under pytest / TESTING flag unless
    # explicitly enabled in test_config (allowing CSRF integration tests).
    if app.config.get("TESTING") and "WTF_CSRF_ENABLED" not in (test_config or {}):
        app.config["WTF_CSRF_ENABLED"] = False

    # Initialize CSRF protection (Flask-WTF)
    # The frontend must send the token in the X-CSRFToken request header for
    # all state-changing requests (POST / PUT / DELETE).
    csrf = CSRFProtect(app)

    # Initialize CORS safely with credential support
    CORS(app, origins=cors_allowed, supports_credentials=True)

    # Configure Rate Limiting
    rate_limit_login = os.getenv("RATE_LIMIT_LOGIN", "10 per minute")
    rate_limit_simulate = os.getenv("RATE_LIMIT_SIMULATE", "60 per minute")

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://"
    )
    app.limiter = limiter

    # Initialize Database
    init_db(
        db_path=app.config["DATABASE_PATH"],
        app_env=app.config["AUTHGUARD_ENV"],
        demo_mode=app.config["DEMO_MODE"],
        seed_demo=app.config["SEED_DEMO_USER"],
        demo_user=app.config["DEMO_ADMIN_USER"],
        demo_pass=app.config["DEMO_ADMIN_PASSWORD"]
    )

    # ---------------------------------------------------------
    # Authentication & Authorization Helpers
    # ---------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Authentication required. Please log in."
                }), 401
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Authentication required. Please log in."
                }), 401
            if session.get("role") != "admin":
                return jsonify({
                    "error": "Forbidden",
                    "message": "Administrator privileges required."
                }), 403
            return f(*args, **kwargs)
        return decorated_function

    # ---------------------------------------------------------
    # Static & Frontend Delivery
    # ---------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        frontend_dir = ROOT_DIR / "frontend"
        if (frontend_dir / "index.html").exists():
            return send_from_directory(str(frontend_dir), "index.html")
        return jsonify({"message": "AuthGuard-X API Operational", "frontend": "index.html not found"}), 200

    # ---------------------------------------------------------
    # Health & System Status
    # ---------------------------------------------------------
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "AuthGuard-X",
            "environment": app.config["AUTHGUARD_ENV"],
            "demo_mode": app.config["DEMO_MODE"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    # ---------------------------------------------------------
    # Authentication Endpoints
    # ---------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    @app.route("/login", methods=["POST"])
    @limiter.limit(rate_limit_login)
    def login():
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"status": "fail", "error": "Invalid JSON body"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"status": "fail", "error": "Username and password required"}), 400

        username = username.strip()
        if len(username) > 64 or len(password) > 128:
            return jsonify({"status": "fail", "error": "Input length exceeded"}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row:
            stored_pw = row["password"]
            if isinstance(stored_pw, str):
                stored_pw = stored_pw.encode("utf-8")
            if bcrypt.checkpw(password.encode("utf-8"), stored_pw):
                # Session fixation protection: clear old session before setting new
                session.clear()
                session["user_id"] = row["id"]
                session["username"] = row["username"]
                session["role"] = row["role"]
                session.permanent = True

                return jsonify({
                    "status": "success",
                    "user": {
                        "id": row["id"],
                        "username": row["username"],
                        "role": row["role"]
                    }
                }), 200

        return jsonify({"status": "fail", "error": "Invalid username or password"}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200

    @app.route("/api/auth/session", methods=["GET"])
    @app.route("/api/auth/status", methods=["GET"])
    def session_status():
        is_auth = "user_id" in session
        response_payload = {
            "authenticated": is_auth,
            "environment": app.config["AUTHGUARD_ENV"],
            "demo_mode": app.config["DEMO_MODE"]
        }

        if is_auth:
            response_payload["user"] = {
                "id": session["user_id"],
                "username": session.get("username"),
                "role": session.get("role")
            }
        else:
            # Provide demo credentials hint only in development mode when demo_mode is enabled
            if app.config["AUTHGUARD_ENV"] == "development" and app.config["DEMO_MODE"]:
                response_payload["demo_credentials"] = {
                    "username": app.config["DEMO_ADMIN_USER"],
                    "password": app.config["DEMO_ADMIN_PASSWORD"]
                }
            else:
                response_payload["demo_credentials"] = None

        return jsonify(response_payload), 200

    @app.route("/api/auth/csrf-token", methods=["GET"])
    def csrf_token():
        """
        Returns a CSRF token for the calling client.

        This endpoint is intentionally accessible to both authenticated and
        unauthenticated clients so the login form can obtain a token before
        the user has a session.  The token is generated via Flask-WTF and
        is tied to the current session via a signed HMAC.
        """
        token = generate_csrf()
        return jsonify({"csrf_token": token}), 200

    # ---------------------------------------------------------
    # Incident & Attack Log Endpoints
    # ---------------------------------------------------------

    @app.route("/api/incidents", methods=["GET"])
    @login_required
    def get_incidents():
        """
        Enhanced incident listing with search, filter, sort and pagination.

        When no pagination parameters (page / per_page) are supplied the
        endpoint preserves the original flat-array response shape so that
        existing clients are not broken.  When pagination parameters are
        present a paginated envelope is returned instead.
        """
        # --- Query parameter extraction ---
        search = request.args.get("search", "").strip() or None
        severity = request.args.get("severity", "").strip() or None
        status = request.args.get("status", "all").strip()
        source = request.args.get("source", "all").strip()
        sort_by = request.args.get("sort_by", "id").strip()
        sort_dir = request.args.get("sort_dir", "desc").strip()
        date_from = request.args.get("date_from", "").strip() or None
        date_to = request.args.get("date_to", "").strip() or None
        assigned_to = request.args.get("assigned_to", "").strip() or None

        # Determine whether the caller wants paginated output
        page_raw = request.args.get("page")
        per_page_raw = request.args.get("per_page")
        paginated = page_raw is not None or per_page_raw is not None

        try:
            page = max(1, int(page_raw)) if page_raw else 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = max(1, min(100, int(per_page_raw))) if per_page_raw else 25
        except (ValueError, TypeError):
            per_page = 25

        count_sql, data_sql, params = _build_incidents_query(
            search=search,
            severity=severity,
            status=status,
            source=source,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page if paginated else None,
            per_page=per_page,
            date_from=date_from,
            date_to=date_to,
            assigned_to=assigned_to,
        )

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        # Total count (for pagination metadata)
        c.execute(count_sql, params)
        total = c.fetchone()[0]

        if paginated:
            offset = (page - 1) * per_page
            paged_sql = data_sql + " LIMIT ? OFFSET ?"
            c.execute(paged_sql, params + [per_page, offset])
        else:
            c.execute(data_sql, params)

        rows = c.fetchall()
        conn.close()

        incidents = [_row_to_dict(r) for r in rows]

        if paginated:
            total_pages = max(1, math.ceil(total / per_page))
            return jsonify({
                "incidents": incidents,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                }
            }), 200

        # Backward-compatible flat-array response (no pagination params supplied)
        return jsonify(incidents), 200

    @app.route("/get_logs", methods=["GET"])
    @login_required
    def get_logs():
        """
        Legacy flat-array endpoint for backward compatibility.

        Delegates to the same query builder with default parameters and always
        returns a plain JSON array (no pagination envelope).
        """
        count_sql, data_sql, params = _build_incidents_query()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(data_sql, params)
        rows = c.fetchall()
        conn.close()

        return jsonify([_row_to_dict(r) for r in rows]), 200

    @app.route("/api/incidents/<int:id>", methods=["GET"])
    @login_required
    def get_incident_detail(id: int):
        """Returns full detail for a single incident by primary key, including case status."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(
            """
            SELECT 
                logs.id, logs.username, logs.attack, logs.behavior, logs.risk, logs.ip, logs.location, logs.time, logs.resolved, logs.is_simulated,
                cases.status, cases.assigned_to, cases.assigned_username, cases.assigned_at,
                cases.investigation_started_at, cases.contained_at, cases.resolved_at, cases.resolution_summary, cases.updated_at
            FROM logs
            LEFT JOIN cases ON logs.id = cases.incident_id
            WHERE logs.id = ?
            """,
            (id,)
        )
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        return jsonify(_row_to_dict(row)), 200

    @app.route("/api/incidents/simulate", methods=["POST"])
    @app.route("/log_attack", methods=["POST"])
    @login_required
    @limiter.limit(rate_limit_simulate)
    def log_attack():
        """
        Logs a simulated attack incident.

        SECURITY: is_simulated is ALWAYS forced to 1 (True) regardless of
        what the client sends.  This endpoint exists exclusively for simulation
        / demo data and must never be used to ingest real telemetry.  The
        client cannot override this flag.
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        # Input sanitization and validation
        attack = data.get("attack")
        risk = data.get("risk")
        behavior = data.get("behavior", "manual")
        username = data.get("username", session.get("username", "simulator"))
        simulated_location = data.get("simulated_location")

        # SECURITY: Always set is_simulated=1 for this endpoint regardless of
        # the client-supplied value.  The simulate endpoint is ONLY for demo
        # / simulation data and the caller cannot override this flag.
        is_simulated = True

        if not attack or risk is None:
            return jsonify({"error": "Bad Request", "message": "'attack' and 'risk' are required"}), 400

        try:
            risk = int(risk)
            if risk < 0 or risk > 100:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "Bad Request", "message": "'risk' must be an integer between 0 and 100"}), 400

        attack = str(attack)[:100].strip()
        behavior = str(behavior)[:100].strip()
        username = str(username)[:64].strip()

        # Resolve IP and Location safely
        client_ip = request.remote_addr or "127.0.0.1"

        if simulated_location and isinstance(simulated_location, str):
            location = f"{simulated_location[:60]} (Simulated)"
        else:
            base_loc = resolve_ip_location(
                client_ip,
                enable_external_geoip=app.config["ENABLE_EXTERNAL_GEOIP"]
            )
            location = f"{base_loc} (Simulated)"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)
        """, (username, attack, behavior, risk, client_ip, location, timestamp))
        log_id = c.lastrowid

        # Sprint 2: Create associated case in 'new' state and record audit log in same transaction
        c.execute("""
            INSERT INTO cases (incident_id, status, created_at, updated_at)
            VALUES (?, 'new', ?, ?)
        """, (log_id, timestamp, timestamp))

        actor_id = session.get("user_id") or 1
        actor_name = session.get("username", "simulator")
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'incident_created', NULL, 'new', 'Incident simulated and registered in SOC case queue', ?)
        """, (log_id, actor_id, actor_name, timestamp))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Incident logged successfully",
            "incident": {
                "id": log_id,
                "username": username,
                "attack": attack,
                "behavior": behavior,
                "risk": risk,
                "ip": client_ip,
                "location": location,
                "time": timestamp,
                "resolved": 0,
                "is_simulated": is_simulated,
                "status": "new",
                "assigned_to": None,
                "assigned_username": None,
            }
        }), 201

    # ---------------------------------------------------------
    # Sprint 2: SOC Investigation & Case Management Core Engine
    # ---------------------------------------------------------

    VALID_STATUS_TRANSITIONS = {
        "new": {"investigating"},
        "investigating": {"contained", "resolved"},
        "contained": {"investigating", "resolved"},
        "resolved": {"investigating"},  # Controlled reopening
    }

    def _ensure_case_row(c, incident_id: int):
        """Ensures a case row exists for an incident, creating one idempotently if missing.
        Preserves historical resolution times as NULL (unknown) rather than setting to creation time.
        """
        c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
        case_row = c.fetchone()
        if not case_row:
            c.execute("SELECT time, resolved FROM logs WHERE id = ?", (incident_id,))
            log_row = c.fetchone()
            if log_row:
                st = "resolved" if log_row["resolved"] == 1 else "new"
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute("""
                    INSERT INTO cases (incident_id, status, created_at, updated_at, resolved_at, resolution_summary, reopen_count, version)
                    VALUES (?, ?, ?, ?, NULL, ?, 0, 1)
                """, (incident_id, st, log_row["time"] or now, now, 'Historical incident' if st == 'resolved' else None))
                c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
                case_row = c.fetchone()
        return case_row

    def _perform_incident_resolution(conn, c, incident_id: int, user_id: int, user_role: str, user_name: str, summary: str, expected_version: int = None):
        """
        Unified incident resolution backend service.
        Enforces:
          1. Role-based authorization & case ownership (analyst A cannot resolve analyst B's incident)
          2. Case lifecycle validation (must be currently in 'investigating' or 'contained')
          3. Required resolution documentation (summary >= 5 characters)
          4. Concurrency safety (optimistic locking)
          5. Atomic updates to logs (resolved=1) and cases (status='resolved')
          6. Chronological audit logging
        """
        c.execute("SELECT id, resolved FROM logs WHERE id = ?", (incident_id,))
        log_row = c.fetchone()
        if not log_row:
            return jsonify({"error": "Not Found", "message": f"Incident {incident_id} not found"}), 404

        case_row = _ensure_case_row(c, incident_id)
        current_status = case_row["status"]
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        current_version = case_row["version"]

        # 1. Role-based authorization & Case ownership enforcement
        if user_role != "admin":
            if current_assignee_id is not None and current_assignee_id != user_id:
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can resolve this incident."
                }), 403
            if current_assignee_id is None:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Incident is unassigned. An analyst must claim the incident and start investigation before resolving it."
                }), 403

        # 2. Case lifecycle validation (must be in 'investigating' or 'contained')
        if current_status not in ("investigating", "contained"):
            if current_status == "resolved":
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Incident {incident_id} is already resolved. Reopen the investigation before applying new resolution."
                }), 400
            else:
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Invalid status transition from '{current_status}' to 'resolved'. Incident must be in 'investigating' or 'contained' state before resolution."
                }), 400

        # 3. Required resolution documentation (>= 5 chars)
        if not summary or not isinstance(summary, str) or len(summary.strip()) < 5:
            return jsonify({
                "error": "Bad Request",
                "message": "A documented resolution summary of at least 5 characters is required to resolve a case."
            }), 400
        summary = summary.strip()[:2000]

        # 4. Concurrency safety (Optimistic locking)
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
                if expected_version != current_version:
                    return jsonify({
                        "error": "Conflict",
                        "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}. Please reload latest state and retry.",
                        "current_version": current_version
                    }), 409
            except (ValueError, TypeError):
                pass

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 5. Atomic conditional update to both cases and logs
        c.execute("""
            UPDATE cases
            SET status = 'resolved',
                resolved_at = ?,
                resolution_summary = ?,
                updated_at = ?,
                version = version + 1
            WHERE incident_id = ? AND version = ? AND status = ?
        """, (now, summary, now, incident_id, current_version, current_status))

        if c.rowcount == 0:
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent update conflict detected. The case was modified by another operation.",
                "current_version": current_version
            }), 409

        c.execute("UPDATE logs SET resolved = 1 WHERE id = ?", (incident_id,))

        # 6. Audit logging
        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'incident_resolved', ?, 'resolved', ?, ?)
        """, (incident_id, user_id, user_name, current_status, f"Case resolved by {user_name}. Summary: {summary}", now))

        conn.commit()

        c.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,))
        updated_case = dict(c.fetchone())

        return jsonify({
            "status": "success",
            "message": f"Incident {incident_id} successfully resolved",
            "case": updated_case,
            "id": incident_id
        }), 200

    @app.route("/api/incidents/<int:id>/resolve", methods=["POST"])
    @app.route("/resolve_incident/<int:id>", methods=["POST"])
    @login_required
    def resolve_incident(id: int):
        data = request.get_json(silent=True) or {}
        summary = None
        expected_version = None
        if isinstance(data, dict):
            summary = data.get("resolution_summary") or data.get("summary")
            expected_version = data.get("version")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        user_role = session.get("role", "analyst")
        user_id = session.get("user_id")
        user_name = session.get("username", "analyst")

        resp, code = _perform_incident_resolution(conn, c, id, user_id, user_role, user_name, summary, expected_version)
        conn.close()
        return resp, code

    @app.route("/api/incidents/clear", methods=["POST"])
    @app.route("/clear_logs", methods=["POST"])
    @admin_required
    def clear_logs():
        data = request.get_json(silent=True) or {}
        force_purge = isinstance(data, dict) and data.get("force_purge_investigations") is True
        purge_reason = (data.get("purge_reason") if isinstance(data, dict) else "") or ""
        purge_reason = str(purge_reason).strip()

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM logs")
        logs_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cases")
        cases_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved'")
        active_cases = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_notes")
        notes_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_evidence")
        evidence_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incident_audit_log")
        audit_count = c.fetchone()[0]

        total_incident_records = logs_count + cases_count + notes_count + evidence_count + audit_count

        if total_incident_records > 0:
            if not force_purge:
                conn.close()
                return jsonify({
                    "status": "fail",
                    "error": "Incident records and case history exist. Purge requires administrative authorization with 'force_purge_investigations': true and a mandatory 'purge_reason' (at least 5 characters).",
                    "existing_records": {
                        "logs": logs_count,
                        "cases": cases_count,
                        "active_cases": active_cases,
                        "notes": notes_count,
                        "evidence": evidence_count,
                        "audit_entries": audit_count
                    }
                }), 400

            if len(purge_reason) < 5:
                conn.close()
                return jsonify({
                    "status": "fail",
                    "error": "Administrative purge requires a documented 'purge_reason' of at least 5 characters explaining the justification for clearing SOC history."
                }), 400

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id", 1)
        admin_username = session.get("username", "admin")

        # Persist system-level administrative audit log entry BEFORE wiping incident data
        import json
        c.execute("""
            INSERT INTO system_audit_log (actor_id, actor_username, action, target, reason, details, created_at)
            VALUES (?, ?, 'administrative_purge', 'incidents_and_cases', ?, ?, ?)
        """, (admin_id, admin_username, purge_reason or "System log reset", json.dumps({
            "purged_logs": logs_count,
            "purged_cases": cases_count,
            "purged_notes": notes_count,
            "purged_evidence": evidence_count,
            "purged_audit_entries": audit_count
        }), now))

        # Transactional purge of investigation data and incident logs
        c.execute("DELETE FROM incident_audit_log")
        c.execute("DELETE FROM incident_evidence")
        c.execute("DELETE FROM incident_notes")
        c.execute("DELETE FROM cases")
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        return jsonify({
            "status": "success",
            "message": "All incident logs and investigation records cleared",
            "purged_records": {
                "logs": logs_count,
                "cases": cases_count,
                "notes": notes_count,
                "evidence": evidence_count,
                "audit_entries": audit_count
            }
        }), 200

    @app.route("/api/incidents/<int:id>/case", methods=["GET"])
    @login_required
    def get_incident_case(id: int):
        """Returns full case details, notes, evidence metadata, and audit timeline for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("""
            SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
            FROM logs WHERE id = ?
        """, (id,))
        incident_row = c.fetchone()
        if not incident_row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        conn.commit()

        # Notes ordered chronologically
        c.execute("""
            SELECT id, incident_id, author_id, author_username, content, created_at, updated_at
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        notes = [dict(r) for r in c.fetchall()]

        # Evidence references ordered chronologically
        c.execute("""
            SELECT id, incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at
            FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        evidence = [dict(r) for r in c.fetchall()]

        # Audit activity history ordered chronologically
        c.execute("""
            SELECT id, incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        activity = [dict(r) for r in c.fetchall()]

        conn.close()

        case_dict = dict(case_row) if case_row else {}

        return jsonify({
            "incident": _row_to_dict(incident_row),
            "case": case_dict,
            "notes": notes,
            "evidence": evidence,
            "activity": activity,
        }), 200

    @app.route("/api/incidents/<int:id>/case", methods=["PATCH"])
    @app.route("/api/incidents/<int:id>/status", methods=["POST"])
    @login_required
    def update_case_status(id: int):
        """
        Updates the case lifecycle status enforcing valid state transitions and RBAC.
        Valid transitions:
          - new -> investigating
          - investigating -> contained
          - investigating -> resolved (requires resolution_summary)
          - contained -> resolved (requires resolution_summary)
          - contained -> investigating
          - resolved -> investigating (reopening, requires reopen_reason)
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        target_status = data.get("status")
        if not target_status or not isinstance(target_status, str):
            return jsonify({"error": "Bad Request", "message": "'status' field is required"}), 400
        target_status = target_status.strip().lower()

        resolution_summary = data.get("resolution_summary")
        reopen_reason = data.get("reopen_reason") or data.get("summary")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_status = case_row["status"]
        current_assignee_id = case_row["assigned_to"]

        # Validate lifecycle state transition
        allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            conn.close()
            return jsonify({
                "error": "Bad Request",
                "message": f"Invalid status transition from '{current_status}' to '{target_status}'. Allowed transitions: {sorted(list(allowed))}."
            }), 400

        # RBAC Check:
        user_role = session.get("role", "analyst")
        user_id = session.get("user_id")
        user_name = session.get("username", "analyst")

        if user_role != "admin":
            # If case is assigned to another analyst, forbid status alteration
            if current_assignee_id is not None and current_assignee_id != user_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Incident is assigned to another analyst. Only the assigned analyst or an administrator can modify its status."
                }), 403

        # Validate required documentation
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Delegate resolution to unified resolution engine
        if target_status == "resolved":
            resp, code = _perform_incident_resolution(conn, c, id, user_id, user_role, user_name, resolution_summary, data.get("version"))
            conn.close()
            return resp, code

        # Concurrency safety: optimistic locking check
        expected_version = data.get("version")
        current_version = case_row["version"]
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
                if expected_version != current_version:
                    conn.close()
                    return jsonify({
                        "error": "Conflict",
                        "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}. Please reload latest state and retry.",
                        "current_version": current_version
                    }), 409
            except (ValueError, TypeError):
                pass

        # Execute transition in atomic transaction
        auto_assigned = False
        if current_status == "resolved" and target_status == "investigating":
            if not reopen_reason or not isinstance(reopen_reason, str) or len(reopen_reason.strip()) < 5:
                conn.close()
                return jsonify({
                    "error": "Bad Request",
                    "message": "A documented reopen reason of at least 5 characters is required to reopen a case."
                }), 400
            reopen_reason = reopen_reason.strip()[:2000]

            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    resolved_at = NULL,
                    reopen_count = reopen_count + 1,
                    version = version + 1,
                    updated_at = ?
                WHERE incident_id = ? AND version = ? AND status = 'resolved'
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif current_status == "new" and target_status == "investigating" and current_assignee_id is None:
            # Auto-claim unassigned case when analyst starts investigating
            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    assigned_to = ?,
                    assigned_username = ?,
                    assigned_at = ?,
                    investigation_started_at = COALESCE(investigation_started_at, ?),
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = 'new'
            """, (user_id, user_name, now, now, now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            auto_assigned = True
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif target_status == "investigating":
            c.execute("""
                UPDATE cases
                SET status = 'investigating',
                    investigation_started_at = COALESCE(investigation_started_at, ?),
                    resolved_at = NULL,
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = ?
            """, (now, now, id, current_version, current_status))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))
        elif target_status == "contained":
            c.execute("""
                UPDATE cases
                SET status = 'contained',
                    contained_at = ?,
                    updated_at = ?,
                    version = version + 1
                WHERE incident_id = ? AND version = ? AND status = ?
            """, (now, now, id, current_version, current_status))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent update conflict detected.",
                    "current_version": current_version
                }), 409
            c.execute("UPDATE logs SET resolved = 0 WHERE id = ?", (id,))

        # Record Audit Log Entries
        action_name = "status_change"
        audit_desc = f"Status transitioned from {current_status} to {target_status}"
        if current_status == "resolved" and target_status == "investigating":
            action_name = "incident_reopened"
            audit_desc = f"Case reopened by {user_name}. Reason: {reopen_reason}"
        elif target_status == "resolved":
            action_name = "incident_resolved"
            audit_desc = f"Case resolved by {user_name}. Summary: {resolution_summary}"
        elif target_status == "contained":
            action_name = "incident_contained"
            audit_desc = f"Incident marked contained by {user_name}"

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id, user_id, user_name, action_name, current_status, target_status, audit_desc, now))

        if auto_assigned:
            c.execute("""
                INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed on investigation start', ?)
            """, (id, user_id, user_name, user_name, now))

        conn.commit()

        # Fetch updated case
        c.execute("SELECT * FROM cases WHERE incident_id = ?", (id,))
        updated_case = dict(c.fetchone())
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Incident {id} status successfully updated to '{target_status}'",
            "case": updated_case
        }), 200

    @app.route("/api/incidents/<int:id>/assign", methods=["POST"])
    @login_required
    def assign_case(id: int):
        """
        Assigns or reassigns an incident to an analyst or admin.
        RBAC:
          - Admin: can assign or reassign to any analyst/admin, or unassign.
          - Analyst: can claim an unassigned case (assign to self), or unassign their own case. Cannot reassign others' cases.
        """
        data = request.get_json(silent=True) or {}
        unassign = data.get("unassign") is True
        target_uid = data.get("assigned_to")
        target_user_str = data.get("username")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"

        caller_role = session.get("role", "analyst")
        caller_id = session.get("user_id")
        caller_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        expected_version = data.get("version")
        current_version = case_row["version"]
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
                if expected_version != current_version:
                    conn.close()
                    return jsonify({
                        "error": "Conflict",
                        "message": f"Concurrent modification detected. Expected version {expected_version}, but case is at version {current_version}.",
                        "current_version": current_version
                    }), 409
            except (ValueError, TypeError):
                pass

        if unassign or target_uid is None and not target_user_str:
            # Unassign logic
            if caller_role != "admin" and current_assignee_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Only administrators can unassign incidents assigned to another analyst."
                }), 403

            c.execute("""
                UPDATE cases
                SET assigned_to = NULL, assigned_username = NULL, assigned_at = NULL, updated_at = ?, version = version + 1
                WHERE incident_id = ? AND version = ?
            """, (now, id, current_version))
            if c.rowcount == 0:
                conn.close()
                return jsonify({
                    "error": "Conflict",
                    "message": "Concurrent assignment conflict detected.",
                    "current_version": current_version
                }), 409

            c.execute("""
                INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                VALUES (?, ?, ?, 'assignment_change', ?, 'unassigned', 'Case unassigned', ?)
            """, (id, caller_id, caller_name, current_assignee_name, now))

            conn.commit()
            conn.close()
            return jsonify({
                "status": "success",
                "message": f"Incident {id} successfully unassigned",
                "assigned_to": None,
                "assigned_username": None
            }), 200

        # Resolving target user
        if target_uid is not None:
            try:
                target_uid = int(target_uid)
                c.execute("SELECT id, username, role FROM users WHERE id = ?", (target_uid,))
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Bad Request", "message": "Invalid user ID"}), 400
        else:
            c.execute("SELECT id, username, role FROM users WHERE username = ?", (str(target_user_str).strip(),))

        target_user = c.fetchone()
        if not target_user:
            conn.close()
            return jsonify({"error": "Not Found", "message": "Target user not found"}), 404

        target_id = target_user["id"]
        target_name = target_user["username"]

        # RBAC validation:
        if caller_role != "admin":
            # Analyst can only assign to themselves and only if unassigned
            if current_assignee_id is not None and current_assignee_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Only administrators can reassign incidents from another analyst."
                }), 403
            if target_id != caller_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": "Analysts can only claim incidents for themselves."
                }), 403

        c.execute("""
            UPDATE cases
            SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
            WHERE incident_id = ? AND version = ?
        """, (target_id, target_name, now, now, id, current_version))
        if c.rowcount == 0:
            conn.close()
            return jsonify({
                "error": "Conflict",
                "message": "Concurrent assignment conflict detected.",
                "current_version": current_version
            }), 409

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'assignment_change', ?, ?, ?, ?)
        """, (id, caller_id, caller_name, current_assignee_name, target_name, f"Assigned to {target_name} by {caller_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Incident {id} assigned to {target_name}",
            "assigned_to": target_id,
            "assigned_username": target_name
        }), 200

    @app.route("/api/incidents/<int:id>/notes", methods=["GET"])
    @login_required
    def get_case_notes(id: int):
        """Returns all investigation findings and notes for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, author_id, author_username, content, created_at, updated_at
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        notes = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(notes), 200

    @app.route("/api/incidents/<int:id>/notes", methods=["POST"])
    @login_required
    def add_case_note(id: int):
        """Adds a persistent investigation finding or note. Author identity is derived securely from the active session."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        content = data.get("content")
        if not content or not isinstance(content, str) or not content.strip():
            return jsonify({"error": "Bad Request", "message": "Note content cannot be empty"}), 400

        content = content.strip()
        if len(content) > 4000:
            return jsonify({"error": "Bad Request", "message": "Note content exceeds maximum length of 4000 characters"}), 400

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        caller_role = session.get("role", "analyst")
        author_id = session["user_id"]
        author_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ownership enforcement: only assigned analyst or admin can modify owned case
        if caller_role != "admin":
            if current_assignee_id is not None and current_assignee_id != author_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can add investigation notes."
                }), 403
            if current_assignee_id is None:
                # Auto-claim unassigned case when adding a note
                c.execute("""
                    UPDATE cases
                    SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
                    WHERE incident_id = ?
                """, (author_id, author_name, now, now, id))
                c.execute("""
                    INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                    VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed upon note creation', ?)
                """, (id, author_id, author_name, author_name, now))

        c.execute("""
            INSERT INTO incident_notes (incident_id, author_id, author_username, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id, author_id, author_name, content, now, now))
        note_id = c.lastrowid

        c.execute("""
            UPDATE cases SET updated_at = ?, version = version + 1 WHERE incident_id = ?
        """, (now, id))

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'note_added', NULL, ?, ?, ?)
        """, (id, author_id, author_name, str(note_id), f"Investigation note added by {author_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Investigation note added successfully",
            "note": {
                "id": note_id,
                "incident_id": id,
                "author_id": author_id,
                "author_username": author_name,
                "content": content,
                "created_at": now,
                "updated_at": now
            }
        }), 201

    @app.route("/api/incidents/<int:id>/evidence", methods=["GET"])
    @login_required
    def get_case_evidence(id: int):
        """Returns all evidence metadata references associated with an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at
            FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        evidence = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(evidence), 200

    @app.route("/api/incidents/<int:id>/evidence", methods=["POST"])
    @login_required
    def add_case_evidence(id: int):
        """Attaches an evidence metadata reference (log excerpt, pcap reference, external threat link, etc.)."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        title = data.get("title")
        evidence_type = data.get("evidence_type", "log_excerpt")
        source_ref = data.get("source_ref", "")
        description = data.get("description", "")

        if not title or not isinstance(title, str) or not title.strip():
            return jsonify({"error": "Bad Request", "message": "Evidence title cannot be empty"}), 400
        title = title.strip()[:150]

        VALID_EVIDENCE_TYPES = {
            "log_excerpt", "network_pcap", "external_report",
            "ip_reputation", "hash_indicator", "screenshot_ref", "other"
        }
        if evidence_type not in VALID_EVIDENCE_TYPES:
            evidence_type = "other"

        if not isinstance(source_ref, str):
            source_ref = ""
        source_ref = source_ref.strip()[:500]

        # Distinguish validated HTTP(S) URLs from ordinary non-URL evidence identifiers
        lower_ref = source_ref.lower()
        FORBIDDEN_SCHEMES = ("javascript:", "data:", "vbscript:", "file:", "blob:", "ftp:", "about:")
        if any(lower_ref.startswith(s) for s in FORBIDDEN_SCHEMES):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid or unsafe evidence reference format. Dangerous URI schemes are forbidden."
            }), 400

        # If reference contains a URL scheme (e.g. '://') validate that it is HTTP or HTTPS with a valid host
        if "://" in source_ref:
            import urllib.parse
            parsed = urllib.parse.urlparse(source_ref)
            if parsed.scheme.lower() not in ("http", "https"):
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// URLs are allowed."
                }), 400
            if not parsed.netloc:
                return jsonify({
                    "error": "Bad Request",
                    "message": "Malformed URL reference: missing hostname or domain."
                }), 400

        if not isinstance(description, str):
            description = ""
        description = description.strip()[:2000]

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        c.execute("SELECT id FROM logs WHERE id = ?", (id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        case_row = _ensure_case_row(c, id)
        current_assignee_id = case_row["assigned_to"]
        current_assignee_name = case_row["assigned_username"] or "unassigned"
        caller_role = session.get("role", "analyst")
        author_id = session["user_id"]
        author_name = session.get("username", "analyst")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ownership enforcement: only assigned analyst or admin can attach evidence
        if caller_role != "admin":
            if current_assignee_id is not None and current_assignee_id != author_id:
                conn.close()
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Incident is assigned to @{current_assignee_name}. Only the assigned analyst or an administrator can attach evidence."
                }), 403
            if current_assignee_id is None:
                # Auto-claim unassigned case when attaching evidence
                c.execute("""
                    UPDATE cases
                    SET assigned_to = ?, assigned_username = ?, assigned_at = ?, updated_at = ?, version = version + 1
                    WHERE incident_id = ?
                """, (author_id, author_name, now, now, id))
                c.execute("""
                    INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
                    VALUES (?, ?, ?, 'assignment_change', 'unassigned', ?, 'Auto-claimed upon evidence attachment', ?)
                """, (id, author_id, author_name, author_name, now))

        c.execute("""
            INSERT INTO incident_evidence (incident_id, title, evidence_type, source_ref, description, added_by_id, added_by_username, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id, title, evidence_type, source_ref, description, author_id, author_name, now))
        evidence_id = c.lastrowid

        c.execute("""
            UPDATE cases SET updated_at = ?, version = version + 1 WHERE incident_id = ?
        """, (now, id))

        c.execute("""
            INSERT INTO incident_audit_log (incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at)
            VALUES (?, ?, ?, 'evidence_added', NULL, ?, ?, ?)
        """, (id, author_id, author_name, str(evidence_id), f"Evidence '{title}' ({evidence_type}) attached by {author_name}", now))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Evidence reference attached successfully",
            "evidence": {
                "id": evidence_id,
                "incident_id": id,
                "title": title,
                "evidence_type": evidence_type,
                "source_ref": source_ref,
                "description": description,
                "added_by_id": author_id,
                "added_by_username": author_name,
                "created_at": now
            }
        }), 201

    @app.route("/api/incidents/<int:id>/activity", methods=["GET"])
    @login_required
    def get_case_activity(id: int):
        """Returns chronological investigation audit trail for an incident."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, incident_id, actor_id, actor_username, action, before_value, after_value, description, created_at
            FROM incident_audit_log
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
        """, (id,))
        activity = [dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(activity), 200

    @app.route("/api/cases/my-queue", methods=["GET"])
    @login_required
    def get_my_queue():
        """Returns cases assigned to the current authenticated analyst."""
        current_uid = session["user_id"]
        status = request.args.get("status", "all").strip()
        search = request.args.get("search", "").strip() or None
        severity = request.args.get("severity", "").strip() or None
        page_raw = request.args.get("page")
        per_page_raw = request.args.get("per_page")
        paginated = page_raw is not None or per_page_raw is not None

        try:
            page = max(1, int(page_raw)) if page_raw else 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = max(1, min(100, int(per_page_raw))) if per_page_raw else 25
        except (ValueError, TypeError):
            per_page = 25

        count_sql, data_sql, params = _build_incidents_query(
            search=search,
            severity=severity,
            status=status,
            assigned_to=current_uid,
            sort_by="risk",
            sort_dir="desc",
            page=page if paginated else None,
            per_page=per_page,
        )

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(count_sql, params)
        total = c.fetchone()[0]

        if paginated:
            offset = (page - 1) * per_page
            paged_sql = data_sql + " LIMIT ? OFFSET ?"
            c.execute(paged_sql, params + [per_page, offset])
        else:
            c.execute(data_sql, params)

        rows = c.fetchall()
        conn.close()

        cases = [_row_to_dict(r) for r in rows]

        if paginated:
            total_pages = max(1, math.ceil(total / per_page))
            return jsonify({
                "cases": cases,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                }
            }), 200

        return jsonify(cases), 200

    @app.route("/api/cases/unassigned", methods=["GET"])
    @login_required
    def get_unassigned_cases():
        """Returns open cases that are unassigned."""
        count_sql, data_sql, params = _build_incidents_query(
            status="open",
            assigned_to="unassigned",
            sort_by="risk",
            sort_dir="desc",
        )
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(data_sql, params)
        rows = c.fetchall()
        conn.close()
        return jsonify([_row_to_dict(r) for r in rows]), 200

    @app.route("/api/metrics/investigations", methods=["GET"])
    @login_required
    def get_investigation_metrics():
        """Returns aggregated SOC case management and workflow metrics."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        user_id = session.get("user_id")

        # Counts by status
        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'new'")
        new_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'investigating'")
        investigating_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'contained'")
        contained_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM cases WHERE status = 'resolved'")
        resolved_count = c.fetchone()[0]

        # Unassigned open cases
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved' AND assigned_to IS NULL")
        unassigned_count = c.fetchone()[0]

        # Cases in user's queue (assigned to caller and not resolved)
        c.execute("SELECT COUNT(*) FROM cases WHERE status != 'resolved' AND assigned_to = ?", (user_id,))
        my_queue_count = c.fetchone()[0]

        # Critical unresolved cases
        c.execute("""
            SELECT COUNT(*) 
            FROM logs 
            JOIN cases ON logs.id = cases.incident_id 
            WHERE logs.risk >= 80 AND cases.status != 'resolved'
        """)
        critical_unresolved = c.fetchone()[0]

        # Average resolution duration: exclude unavailable (NULL) or untrustworthy (diff <= 0 or resolved_at == created_at) timestamps
        c.execute("""
            SELECT created_at, investigation_started_at, resolved_at 
            FROM cases 
            WHERE status = 'resolved' AND resolved_at IS NOT NULL
        """)
        resolved_rows = c.fetchall()

        durations = []
        for r in resolved_rows:
            try:
                res_str = r["resolved_at"]
                created_str = r["created_at"]
                start_str = r["investigation_started_at"] or created_str
                # Exclude if resolution timestamp equals creation timestamp (indicates untrustworthy / legacy bulk resolved)
                if not res_str or res_str == created_str:
                    continue
                res_time = datetime.strptime(res_str, "%Y-%m-%d %H:%M:%S")
                start_time = datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S")
                diff = (res_time - start_time).total_seconds()
                if diff > 0:
                    durations.append(diff)
            except Exception:
                pass

        conn.close()

        avg_seconds = round(sum(durations) / len(durations), 1) if durations else None
        avg_human = None
        if avg_seconds is not None:
            mins, secs = divmod(int(avg_seconds), 60)
            hours, mins = divmod(mins, 60)
            if hours > 0:
                avg_human = f"{hours}h {mins}m"
            elif mins > 0:
                avg_human = f"{mins}m {secs}s"
            else:
                avg_human = f"{secs}s"

        return jsonify({
            "new": new_count,
            "investigating": investigating_count,
            "contained": contained_count,
            "resolved": resolved_count,
            "unassigned": unassigned_count,
            "my_queue": my_queue_count,
            "critical_unresolved": critical_unresolved,
            "avg_resolution_seconds": avg_seconds,
            "avg_resolution_human": avg_human or "N/A"
        }), 200

    @app.route("/api/users/analysts", methods=["GET"])
    @login_required
    def get_analyst_users():
        """Returns list of active analysts and administrators for case assignment selector."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users ORDER BY username ASC")
        rows = c.fetchall()
        conn.close()
        return jsonify([{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows]), 200

    @app.route("/api/users/create", methods=["POST"])
    @admin_required
    def create_user():
        """Administrator-only user provisioning for adding SOC analysts or administrators."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "analyst")

        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "Bad Request", "message": "Username and password required"}), 400

        username = username.strip()
        if len(username) < 3 or len(username) > 64:
            return jsonify({"error": "Bad Request", "message": "Username must be between 3 and 64 characters"}), 400

        if len(password) < 8 or len(password) > 128:
            return jsonify({"error": "Bad Request", "message": "Password must be between 8 and 128 characters"}), 400

        if role not in ("analyst", "admin"):
            role = "analyst"

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({"error": "Conflict", "message": f"Username '{username}' already exists"}), 409

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute("""
            INSERT INTO users (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (username, pw_hash, role, now))
        new_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"User '{username}' created successfully",
            "user": {
                "id": new_id,
                "username": username,
                "role": role,
                "created_at": now
            }
        }), 201

    # ---------------------------------------------------------
    # Metrics Endpoint
    # ---------------------------------------------------------
    @app.route("/api/metrics", methods=["GET"])
    @login_required
    def get_metrics():
        """
        Returns aggregated security metrics for the dashboard.

        Health score formula:
          Start at 100
          - 8 per unresolved critical incident  (risk >= 80)
          - 5 per unresolved high incident       (60 <= risk < 80)
          - 2 per unresolved medium incident     (40 <= risk < 60)
          - 0 for unresolved low incidents       (risk < 40)
          Minimum value: 0
        """
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()

        today_str = datetime.now().strftime("%Y-%m-%d")
        week_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        c.execute("SELECT COUNT(*) FROM logs")
        total_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0")
        open_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 1")
        resolved_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ?", (80,))
        critical_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ? AND risk < ?", (60, 80))
        high_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk >= ? AND risk < ?", (40, 60))
        medium_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE risk < ?", (40,))
        low_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE is_simulated = 1")
        simulated_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE is_simulated = 0")
        telemetry_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE time >= ?", (f"{today_str} 00:00:00",))
        today_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE time >= ?", (f"{week_start} 00:00:00",))
        week_count = c.fetchone()[0]

        # Unresolved counts per severity level (for health score)
        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ?", (80,))
        open_critical = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ? AND risk < ?", (60, 80))
        open_high = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE resolved = 0 AND risk >= ? AND risk < ?", (40, 60))
        open_medium = c.fetchone()[0]

        conn.close()

        health_score = max(
            0,
            100
            - (open_critical * 8)
            - (open_high * 5)
            - (open_medium * 2)
        )

        return jsonify({
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "simulated_count": simulated_count,
            "telemetry_count": telemetry_count,
            "health_score": health_score,
            "today_count": today_count,
            "week_count": week_count,
        }), 200

    # ---------------------------------------------------------
    # Secure Error Handlers
    # ---------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad Request", "message": str(e.description if hasattr(e, "description") else e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not Found", "message": "The requested resource was not found"}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        # Do not leak internal exception details to client
        return jsonify({"error": "Internal Server Error", "message": "An internal error occurred."}), 500

    return app


# Application entry point
app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("AUTHGUARD_ENV", "development").lower() == "development"
    print(f"[*] Starting AuthGuard-X Server on http://{host}:{port} (env: {app.config['AUTHGUARD_ENV']})")
    app.run(host=host, port=port, debug=debug_mode)

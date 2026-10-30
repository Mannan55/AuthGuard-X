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
    return conn


def init_db(db_path: str, app_env: str, demo_mode: bool, seed_demo: bool,
            demo_user: str, demo_pass: str):
    """
    Initializes database tables and safely migrates schema if needed.
    Demo user is explicitly seeded ONLY in development environment when enabled.
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

    # Safe demo user provisioning
    # Strictly prohibited in production!
    if app_env == "development" and demo_mode and seed_demo:
        c.execute("SELECT id FROM users WHERE username = ?", (demo_user,))
        existing_user = c.fetchone()
        if not existing_user and demo_user and demo_pass:
            pw_hash = bcrypt.hashpw(demo_pass.encode("utf-8"), bcrypt.gensalt(rounds=12))
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (demo_user, pw_hash, "admin", now)
            )
            print(f"[AUTHGUARD-INIT] Development demo user provisioned: '{demo_user}'")

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
_INCIDENTS_SORT_ALLOWLIST = {"id", "risk", "time", "username", "attack"}


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
):
    """
    Constructs a parameterized SQL query for the incidents/logs table.

    All user-supplied filter values are bound via parameters (never interpolated).
    The sort column is validated against an explicit allowlist before insertion.

    Returns (count_sql, data_sql, params, limit, offset) where limit/offset are
    None when pagination is not requested (page=None).
    """
    conditions = []
    params = []

    # --- Search filter (LIKE, parameterized) ---
    if search:
        term = f"%{search}%"
        conditions.append(
            "(username LIKE ? OR attack LIKE ? OR behavior LIKE ?)"
        )
        params.extend([term, term, term])

    # --- Severity filter (maps to risk score ranges) ---
    if severity:
        severity = severity.lower()
        if severity == "critical":
            conditions.append("risk >= ?")
            params.append(80)
        elif severity == "high":
            conditions.append("risk >= ? AND risk < ?")
            params.extend([60, 80])
        elif severity == "medium":
            conditions.append("risk >= ? AND risk < ?")
            params.extend([40, 60])
        elif severity == "low":
            conditions.append("risk < ?")
            params.append(40)

    # --- Status filter ---
    if status and status != "all":
        if status == "open":
            conditions.append("resolved = ?")
            params.append(0)
        elif status == "resolved":
            conditions.append("resolved = ?")
            params.append(1)

    # --- Source filter ---
    if source and source != "all":
        if source == "simulated":
            conditions.append("is_simulated = ?")
            params.append(1)
        elif source == "telemetry":
            conditions.append("is_simulated = ?")
            params.append(0)

    # --- Date range filter ---
    if date_from:
        try:
            datetime.strptime(date_from, "%Y-%m-%d")
            conditions.append("time >= ?")
            params.append(f"{date_from} 00:00:00")
        except ValueError:
            pass  # Ignore malformed dates silently

    if date_to:
        try:
            datetime.strptime(date_to, "%Y-%m-%d")
            conditions.append("time <= ?")
            params.append(f"{date_to} 23:59:59")
        except ValueError:
            pass

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # --- Sort column allowlist enforcement (prevents ORDER BY injection) ---
    if sort_by not in _INCIDENTS_SORT_ALLOWLIST:
        sort_by = "id"
    sort_dir = "ASC" if str(sort_dir).lower() == "asc" else "DESC"

    base_select = f"""
        SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
        FROM logs
        {where_clause}
        ORDER BY {sort_by} {sort_dir}
    """

    count_select = f"SELECT COUNT(*) AS total FROM logs {where_clause}"

    return count_select, base_select, params


def _row_to_dict(r):
    """Converts a sqlite3.Row from the logs table to a plain dict."""
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
        "is_simulated": bool(r["is_simulated"]),
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

    # Automatically disable CSRF when running under pytest / TESTING flag so
    # the existing test suite keeps passing without requiring token plumbing.
    if app.config.get("TESTING"):
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
        """Returns full detail for a single incident by primary key."""
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute(
            """
            SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
            FROM logs
            WHERE id = ?
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
                "is_simulated": is_simulated
            }
        }), 201

    @app.route("/api/incidents/<int:id>/resolve", methods=["POST"])
    @app.route("/resolve_incident/<int:id>", methods=["POST"])
    @login_required
    def resolve_incident(id: int):
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("SELECT id, resolved FROM logs WHERE id = ?", (id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not Found", "message": f"Incident {id} not found"}), 404

        c.execute("UPDATE logs SET resolved = 1 WHERE id = ?", (id,))
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Incident {id} resolved successfully",
            "id": id
        }), 200

    @app.route("/api/incidents/clear", methods=["POST"])
    @app.route("/clear_logs", methods=["POST"])
    @admin_required
    def clear_logs():
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "All incident logs cleared"}), 200

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

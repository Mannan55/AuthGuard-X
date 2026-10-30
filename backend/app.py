import os
import sys
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
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4)
    )

    if test_config:
        app.config.update(test_config)

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

    # ---------------------------------------------------------
    # Incident & Attack Log Endpoints
    # ---------------------------------------------------------
    @app.route("/api/incidents", methods=["GET"])
    @app.route("/get_logs", methods=["GET"])
    @login_required
    def get_logs():
        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            SELECT id, username, attack, behavior, risk, ip, location, time, resolved, is_simulated
            FROM logs
            ORDER BY id DESC
        """)
        rows = c.fetchall()
        conn.close()

        logs = []
        for r in rows:
            logs.append({
                "id": r["id"],
                "username": r["username"],
                "attack": r["attack"],
                "behavior": r["behavior"],
                "risk": r["risk"],
                "ip": r["ip"],
                "location": r["location"],
                "time": r["time"],
                "resolved": r["resolved"],
                "is_simulated": bool(r["is_simulated"])
            })

        return jsonify(logs), 200

    @app.route("/api/incidents/simulate", methods=["POST"])
    @app.route("/log_attack", methods=["POST"])
    @login_required
    @limiter.limit(rate_limit_simulate)
    def log_attack():
        """
        Logs an attack incident.
        Explicitly flags whether the incident is simulated/demo data vs real telemetry.
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Bad Request", "message": "Invalid JSON body"}), 400

        # Input sanitization and validation
        attack = data.get("attack")
        risk = data.get("risk")
        behavior = data.get("behavior", "manual")
        username = data.get("username", session.get("username", "simulator"))
        is_simulated = bool(data.get("is_simulated", True))
        simulated_location = data.get("simulated_location")

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

        if is_simulated and simulated_location and isinstance(simulated_location, str):
            location = f"{simulated_location[:60]} (Simulated)"
        else:
            base_loc = resolve_ip_location(
                client_ip,
                enable_external_geoip=app.config["ENABLE_EXTERNAL_GEOIP"]
            )
            location = f"{base_loc} (Simulated)" if is_simulated else base_loc

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection(app.config["DATABASE_PATH"])
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (username, attack, behavior, risk, ip, location, time, resolved, is_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (username, attack, behavior, risk, client_ip, location, timestamp, 1 if is_simulated else 0))
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

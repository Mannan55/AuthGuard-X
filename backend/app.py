from flask import Flask, request, jsonify
import sqlite3, bcrypt, requests
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
DB = "authguard.db"
# Clear logs on server start
attack_logs = []
next_id = 1


# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB,
        role TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        attack TEXT,
        behavior TEXT,
        risk INTEGER,
        ip TEXT,
        location TEXT,
        time TEXT,
        resolved INTEGER DEFAULT 0
    )''')

    # Insert admin safely
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users(username,password,role) VALUES (?,?,?)",
                  ("admin", pw, "admin"))

    conn.commit()
    conn.close()

init_db()

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password.encode(), row[0]):
        return jsonify({"status": "success", "role": row[1]}), 200

    return jsonify({"status": "fail"}), 401

# ---------------- LOG ATTACK ----------------
@app.route("/log_attack", methods=["POST"])
def log_attack():
    data = request.get_json()
    ip = request.remote_addr

    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        location = f"{geo.get('city','')} {geo.get('country','')}"
    except:
        location = "Unknown"

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''INSERT INTO logs(username,attack,behavior,risk,ip,location,time)
        VALUES (?,?,?,?,?,?,?)''',
        (
            data["username"],
            data["attack"],
            data["behavior"],
            data["risk"],
            ip,
            location,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "logged"}), 200

# ---------------- GET LOGS ----------------
@app.route("/get_logs", methods=["GET"])
def get_logs():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r[0],
            "username": r[1],
            "attack": r[2],
            "behavior": r[3],
            "risk": r[4],
            "ip": r[5],
            "location": r[6],
            "time": r[7],
            "resolved": r[8]
        })

    return jsonify(logs)

# ---------------- RESOLVE INCIDENT ----------------
@app.route("/resolve_incident/<int:id>", methods=["POST"])
def resolve_incident(id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE logs SET resolved=1 WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "resolved"}), 200

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


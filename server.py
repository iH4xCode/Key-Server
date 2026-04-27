# server.py (SQLite VERSION)
# pip install flask pyjwt

from flask import Flask, request, jsonify
import time
import hashlib
import os
import jwt
import sqlite3
import uuid

app = Flask(__name__)

# ================= ENV =================
SECRET = os.getenv("SECRET", "CHANGE_THIS_SECRET")
HEADER_SECRET = os.getenv("HEADER_SECRET", "CHANGE_THIS_HEADER_SECRET")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "CHANGE_ADMIN_SECRET")
# =======================================

KEY_TTL = 60
DB_FILE = "licenses.db"


# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        license TEXT PRIMARY KEY,
        hwid TEXT,
        exp INTEGER
    )
    """)

    conn.commit()
    conn.close()

init_db()


def db_execute(query, params=(), fetchone=False, fetchall=False):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(query, params)

    result = None
    if fetchone:
        result = c.fetchone()
    elif fetchall:
        result = c.fetchall()

    conn.commit()
    conn.close()
    return result
# =============================================


# 🔐 Stable key (no rotation)
def generate_runtime_key(hwid: str) -> str:
    seed = f"{SECRET}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


@app.route("/")
def home():
    return "Key Server Running (SQLite)"


# 🔑 GET KEY
@app.route("/get-key", methods=["POST"])
def get_key():
    try:
        if request.headers.get("X-Client-Key") != HEADER_SECRET:
            return jsonify({"error": "unauthorized"}), 403

        data = request.get_json(force=True)
        hwid = data.get("hwid")

        if not hwid:
            return jsonify({"error": "missing hwid"}), 400

        runtime_key = generate_runtime_key(hwid)

        payload = {
            "key": runtime_key,
            "exp": int(time.time()) + KEY_TTL,
            "hwid": hwid
        }

        token = jwt.encode(payload, SECRET, algorithm="HS256")

        return jsonify({"status": "ok", "data": token})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔑 GENERATE LICENSE (ADMIN)
@app.route("/generate-license", methods=["POST"])
def generate_license():
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_SECRET:
            return jsonify({"error": "unauthorized"}), 403

        data = request.json or {}
        duration = data.get("type", "1d")

        license_key = str(uuid.uuid4()).replace("-", "")[:16]
        now = int(time.time())

        if duration == "lifetime":
            exp = 9999999999
        elif duration == "7d":
            exp = now + (7 * 86400)
        elif duration == "3d":
            exp = now + (3 * 86400)
        else:
            exp = now + (1 * 86400)

        db_execute(
            "INSERT INTO licenses (license, hwid, exp) VALUES (?, ?, ?)",
            (license_key, None, exp)
        )

        return jsonify({
            "license": license_key,
            "expires": exp
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔍 VALIDATE LICENSE
@app.route("/validate-license", methods=["POST"])
def validate_license():
    try:
        data = request.json
        license_key = data.get("license")
        hwid = data.get("hwid")

        row = db_execute(
            "SELECT hwid, exp FROM licenses WHERE license=?",
            (license_key,),
            fetchone=True
        )

        if not row:
            return jsonify({"status": "invalid"}), 403

        stored_hwid, exp = row

        # ⏱ expiration
        if exp < int(time.time()):
            return jsonify({"status": "expired"}), 403

        # 🔐 bind device
        if stored_hwid is None:
            db_execute(
                "UPDATE licenses SET hwid=? WHERE license=?",
                (hwid, license_key)
            )

        elif stored_hwid != hwid:
            return jsonify({"status": "device_mismatch"}), 403

        return jsonify({
            "status": "valid",
            "exp": exp
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🧨 RATE LIMIT
REQUEST_LOG = {}

@app.before_request
def rate_limit():
    ip = request.remote_addr
    now = time.time()

    window = 10
    limit = 30

    if ip not in REQUEST_LOG:
        REQUEST_LOG[ip] = []

    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if now - t < window]

    if len(REQUEST_LOG[ip]) >= limit:
        return jsonify({"error": "too many requests"}), 429

    REQUEST_LOG[ip].append(now)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
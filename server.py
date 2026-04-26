# server.py
# pip install flask pyjwt

from flask import Flask, request, jsonify
import time
import hashlib
import os
import jwt

app = Flask(__name__)

# 🔐 ENV variables (Render)
SECRET = os.getenv("SECRET", "CHANGE_THIS_SECRET")
HEADER_SECRET = os.getenv("HEADER_SECRET", "CHANGE_THIS_HEADER_SECRET")

# ⏱️ key expiration (seconds)
KEY_TTL = 60

# optional HWID whitelist
ALLOWED_HWIDS = set([
    # "1234567890",
])


def generate_runtime_key(hwid: str) -> str:
    seed = f"{hwid}:{SECRET}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


@app.route("/")
def home():
    return "Key Server Running"


@app.route("/get-key", methods=["POST"])
def get_key():
    try:
        # 🔒 SECRET HEADER CHECK
        client_header = request.headers.get("X-Client-Key")
        if client_header != HEADER_SECRET:
            return jsonify({"error": "unauthorized"}), 403

        data = request.get_json(force=True)
        hwid = data.get("hwid")

        if not hwid:
            return jsonify({"error": "missing hwid"}), 400

        # 🔒 OPTIONAL: HWID restriction
        if ALLOWED_HWIDS:
            if hwid not in ALLOWED_HWIDS:
                return jsonify({"error": "unauthorized device"}), 403

        # 🔑 generate dynamic key
        runtime_key = generate_runtime_key(hwid)

        # 📦 payload
        payload = {
            "key": runtime_key,
            "exp": int(time.time()) + KEY_TTL,
            "hwid": hwid
        }

        # ✍️ sign JWT
        token = jwt.encode(payload, SECRET, algorithm="HS256")

        return jsonify({
            "status": "ok",
            "data": token
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🧨 basic rate limit
REQUEST_LOG = {}

@app.before_request
def rate_limit():
    ip = request.remote_addr
    now = time.time()

    window = 10
    limit = 20

    if ip not in REQUEST_LOG:
        REQUEST_LOG[ip] = []

    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if now - t < window]

    if len(REQUEST_LOG[ip]) >= limit:
        return jsonify({"error": "too many requests"}), 429

    REQUEST_LOG[ip].append(now)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
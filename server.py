# server.py
# pip install flask pyjwt

from flask import Flask, request, jsonify
import time
import hashlib
import os
import jwt

app = Flask(__name__)

# 🔐 Load secret from environment (Render ENV)
SECRET = os.getenv("SECRET", "CHANGE_THIS_SECRET")

# Optional: whitelist ng allowed HWIDs (pwede mong gawing DB later)
ALLOWED_HWIDS = set([
    # "1234567890",
    # "abcdef123456",
])

# ⏱️ validity ng key (seconds)
KEY_TTL = 60


def generate_runtime_key(hwid: str) -> str:
    """
    Generate dynamic key based on:
    - HWID
    - time window
    - server secret
    """
    time_window = int(time.time() // 60)  # rotate every 60 sec
    seed = f"{hwid}:{time_window}:{SECRET}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


@app.route("/")
def home():
    return "Key Server Running"


@app.route("/get-key", methods=["POST"])
def get_key():
    try:
        data = request.get_json(force=True)

        hwid = data.get("hwid")
        token = data.get("token")  # optional (license system)

        if not hwid:
            return jsonify({"error": "missing hwid"}), 400

        # 🔒 OPTIONAL: restrict devices
        if ALLOWED_HWIDS:
            if hwid not in ALLOWED_HWIDS:
                return jsonify({"error": "unauthorized device"}), 403

        # 🔒 OPTIONAL: verify JWT license
        # if token:
        #     try:
        #         jwt.decode(token, SECRET, algorithms=["HS256"])
        #     except:
        #         return jsonify({"error": "invalid token"}), 403

        # 🔑 generate dynamic key
        runtime_key = generate_runtime_key(hwid)

        # 📦 response payload
        payload = {
            "key": runtime_key,
            "exp": int(time.time()) + KEY_TTL,
            "hwid": hwid
        }

        # ✍️ sign response
        signed_token = jwt.encode(payload, SECRET, algorithm="HS256")

        return jsonify({
            "status": "ok",
            "data": signed_token
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


# 🔐 basic anti-spam (optional simple limiter)
REQUEST_LOG = {}

@app.before_request
def rate_limit():
    ip = request.remote_addr
    now = time.time()

    window = 10  # seconds
    limit = 20   # max requests per window

    if ip not in REQUEST_LOG:
        REQUEST_LOG[ip] = []

    # remove old requests
    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if now - t < window]

    if len(REQUEST_LOG[ip]) >= limit:
        return jsonify({"error": "too many requests"}), 429

    REQUEST_LOG[ip].append(now)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
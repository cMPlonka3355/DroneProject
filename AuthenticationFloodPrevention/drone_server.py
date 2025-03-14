import time
import hmac
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secret key in bytes shared ONLY between trusted drones and the truck
SECRET_KEY = b"supersecurekey"

# Prevent authentication flooding
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # 5 minutes
auth_attempts = {}

def verify_token(token, timestamp):
    """Verify if the received token is valid."""
    expected_token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_token, token)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    ip = request.remote_addr
    current_time = time.time()

    # Block IPs with too many failed attempts
    if ip in auth_attempts and auth_attempts[ip]["blocked_until"]:
        if current_time < auth_attempts[ip]["blocked_until"]:
            return jsonify({"error": "Too many failed attempts. Blocked temporarily."}), 429
        else:
            auth_attempts[ip] = {"count": 0, "blocked_until": None}

    data = request.json
    token = data.get("token")
    timestamp = data.get("timestamp")

    # Check if token is valid
    if verify_token(token, timestamp):
        return jsonify({"message": "Drone authenticated successfully!"}), 200
    else:
        auth_attempts[ip] = auth_attempts.get(ip, {"count": 0, "blocked_until": None})
        auth_attempts[ip]["count"] += 1

        if auth_attempts[ip]["count"] >= MAX_ATTEMPTS:
            auth_attempts[ip]["blocked_until"] = current_time + BLOCK_TIME
            return jsonify({"error": "Too many failed attempts. You are blocked."}), 429

        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
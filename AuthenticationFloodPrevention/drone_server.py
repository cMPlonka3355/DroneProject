import time  # Used to track authentication attempts
import hmac  # Used to verify the authentication token
import hashlib  # SHA-256 hashing functions
from flask import Flask, request, jsonify  # used to create an HTTP server

# Create Flask web app to handle authentication requests
app = Flask(__name__)

# Secret key (same as in the truck) to verify authentication tokens
SECRET_KEY = b"supersecurekey"

# Prevent authentication flooding
MAX_ATTEMPTS = 5  # Maximum number of failed authentication attempts
BLOCK_TIME = 300  # Block time in seconds (5 minutes)
auth_attempts = {}  # track authentication attempts per IP

def verify_token(token, timestamp):
    """Verify if the received token is valid."""

    # Generate the expected token using the same process as the truck
    expected_token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()

    # Compare the expected token with the received token (constant-time comparison for security)
    return hmac.compare_digest(expected_token, token)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Handle authentication requests from the truck."""

    # Get IP of requester
    ip = request.remote_addr
    current_time = time.time()  # current time in seconds

    # Check if the IP is already blocked due to too many failed attempts
    if ip in auth_attempts and auth_attempts[ip]["blocked_until"]:
        if current_time < auth_attempts[ip]["blocked_until"]:
            return jsonify({"error": "Too many failed attempts. Blocked temporarily."}), 429
        else:
            # Reset block status after time expires
            auth_attempts[ip] = {"count": 0, "blocked_until": None}

    # Retrieve the token and timestamp sent by the truck
    data = request.json
    token = data.get("token")
    timestamp = data.get("timestamp")

    # Verify the authentication token
    if verify_token(token, timestamp):
        return jsonify({"message": "Drone authenticated successfully!"}), 200
    else:
        # Track the number of failed attempts for this IP
        auth_attempts[ip] = auth_attempts.get(ip, {"count": 0, "blocked_until": None})
        auth_attempts[ip]["count"] += 1

        # If too many failed attempts, block the IP temporarily
        if auth_attempts[ip]["count"] >= MAX_ATTEMPTS:
            auth_attempts[ip]["blocked_until"] = current_time + BLOCK_TIME
            return jsonify({"error": "Too many failed attempts. You are blocked."}), 429

        return jsonify({"error": "Invalid token"}), 401  # authentication failure

# Start the Flask server to listen for authentication requests
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
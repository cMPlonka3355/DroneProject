import time
import hmac                    # verifying secure token
import hashlib                 # hashing token data
from flask import Flask, request, jsonify  # Flask web server

# Create Flask app to handle incoming HTTP requests
app = Flask(__name__)

# Secret key must match the one used by the truck
SECRET_KEY = b"supersecurekey"

def verify_token(token, timestamp):
    """
    Re-generates the expected token using the secret key and timestamp,
    and compares it to the token received from the truck.
    """
    expected_token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_token, token)

@app.route('/command', methods=['POST'])
def handle_command():
    """
    Handles incoming commands from the truck.
    Only accepts requests with a valid token and recent timestamp.
    """
    # Get JSON data from the truck's request
    data = request.json
    token = data.get("token")
    timestamp = data.get("timestamp")

    # Basic input validation
    if not token or not timestamp:
        return jsonify({"error": "Missing token or timestamp"}), 400

    # Reject old tokens to prevent replay attacks (e.g., from saved requests)
    if abs(time.time() - int(timestamp)) > 30:
        return jsonify({"error": "Token expired"}), 403

    # Verify that the token is correct
    if verify_token(token, timestamp):
        # The token is valid, so you can execute a secure command here
        # (e.g., activate motor, send sensor data, etc.)
        return jsonify({"message": "Command authenticated and accepted"}), 200
    else:
        # Token is invalid – do not execute any command
        return jsonify({"error": "Invalid authentication token"}), 403

# Start the Flask server on port 5000 and listen on all interfaces
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

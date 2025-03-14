import time
import hmac
import hashlib
import requests

SECRET_KEY = b"supersecurekey"
DRONE_IP = "123.456.7.89"  # Replace with actual drone IP

def generate_token():
    """Generate a secure token for authentication."""
    timestamp = int(time.time())
    token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()
    return token, timestamp

def authenticate_with_drone():
    """Send authentication request to a drone."""
    token, timestamp = generate_token()
    response = requests.post(
        f"http://{DRONE_IP}:5000/authenticate",
        json={"token": token, "timestamp": timestamp},
    )

    print("Drone Response:", response.json())

if __name__ == "__main__":
    authenticate_with_drone()
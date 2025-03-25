import time
import hmac            # generating secure message signatures
import hashlib         # hashing the token
import requests        # send HTTP requests to drones

# Shared secret key (must match what's on the drone)
SECRET_KEY = b"supersecurekey"

# Replace with actual IP addresses of drones
DRONE_IPS = ["192.168.1.10","123.456.7.89"]

# Authentication attempt limits
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # Block time in seconds (5 minutes)

# keep track of failed attempts from each drone
failed_attempts = {}

def generate_signed_token():
    """
    Generates a time-based HMAC token using the secret key.
    This token will be verified by the drone.
    """
    timestamp = int(time.time())
    # Create a SHA-256 HMAC token using the timestamp
    token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()
    return token, timestamp

def is_blocked(ip):
    """
    Checks whether a drone IP is temporarily blocked due to failed attempts.
    """
    if ip in failed_attempts:
        info = failed_attempts[ip]
        # If still within the block time window, return True
        if info["count"] >= MAX_ATTEMPTS and time.time() < info["blocked_until"]:
            return True
        elif time.time() >= info["blocked_until"]:
            # Reset if block time has expired
            failed_attempts[ip] = {"count": 0, "blocked_until": 0}
    return False

def record_failed_attempt(ip):
    """
    Updates the failed attempt count for a drone IP.
    If max attempts are reached, blocks it for a set time.
    """
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 1, "blocked_until": 0}
    else:
        failed_attempts[ip]["count"] += 1
        if failed_attempts[ip]["count"] >= MAX_ATTEMPTS:
            failed_attempts[ip]["blocked_until"] = time.time() + BLOCK_TIME

def authenticate_and_send_command(drone_ip):
    """
    Authenticates with the drone and sends a secure command.
    """
    if is_blocked(drone_ip):
        print(f"[BLOCKED] {drone_ip} is temporarily blocked.")
        return

    # Generate token and timestamp for authentication
    token, timestamp = generate_signed_token()

    try:
        # Send POST request with token to drone's /command endpoint
        response = requests.post(
            f"http://{drone_ip}:5000/command",
            json={"token": token, "timestamp": timestamp},
            timeout=3
        )

        # Parse response from drone
        data = response.json()
        if response.status_code == 200:
            print(f"[SUCCESS] Drone {drone_ip} responded: {data}")
        else:
            print(f"[FAIL] Drone {drone_ip} rejected: {data}")
            record_failed_attempt(drone_ip)

    except requests.RequestException as e:
        # Handle network errors (e.g., drone offline)
        print(f"[ERROR] Could not reach drone {drone_ip}: {e}")
        record_failed_attempt(drone_ip)

# Run authentication for all drones
if __name__ == "__main__":
    for drone_ip in DRONE_IPS:
        authenticate_and_send_command(drone_ip)

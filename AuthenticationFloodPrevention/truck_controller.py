import time              # timestamps and delays
import hmac              # creating secure authentication tokens
import hashlib           # SHA-256 hashing (token generation)
import requests          # send HTTP POST requests to the drones

# Shared secret key used to generate and verify authentication tokens
SECRET_KEY = b"supersecurekey"

# Time between reauthentication cycles (in seconds)
REAUTH_INTERVAL = 10

# This is the list of drone IPs to authenticate with.
# These may be replaced dynamically (depending on andrew's part) using a live updated file, etc.
DRONE_IPS = ["192.168.1.10"]

# Rate limiting settings
MAX_ATTEMPTS = 5       # Max failed attempts
BLOCK_TIME = 300       # Block duration in seconds (5 minutes)

# Dictionary to track failed attempts for each drone IP
failed_attempts = {}

def generate_signed_token():
    """
    Generate a signed authentication token using the current timestamp and the shared secret key.
    This token will be sent to the drone and verified using the same shared key.
    """
    timestamp = int(time.time())  # Get the current time (in seconds)
    token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()
    return token, timestamp

def is_blocked(ip):
    """
    Check if a drone IP is currently blocked due to too many failed authentication attempts.
    """
    if ip in failed_attempts:
        info = failed_attempts[ip]
        # If blocked and still within the block period, return True
        if info["count"] >= MAX_ATTEMPTS and time.time() < info["blocked_until"]:
            return True
        elif time.time() >= info["blocked_until"]:
            # If block time has passed, reset the attempt counter
            failed_attempts[ip] = {"count": 0, "blocked_until": 0}
    return False

def record_failed_attempt(ip):
    """
    Record a failed authentication attempt for a given IP.
    If it reaches the limit, block the IP temporarily.
    """
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 1, "blocked_until": 0}
    else:
        failed_attempts[ip]["count"] += 1
        if failed_attempts[ip]["count"] >= MAX_ATTEMPTS:
            failed_attempts[ip]["blocked_until"] = time.time() + BLOCK_TIME

def authenticate_and_send_command(drone_ip):
    """
    Attempt to authenticate with a single drone.
    If authentication fails too many times, block further attempts for a while.
    """
    if is_blocked(drone_ip):
        print(f"[BLOCKED] {drone_ip} is temporarily blocked.")
        return

    # Generate a token and timestamp to send to the drone
    token, timestamp = generate_signed_token()

    try:
        # Send HTTP POST request to the drone's command endpoint
        response = requests.post(
            f"http://{drone_ip}:5000/command",
            json={"token": token, "timestamp": timestamp},
            timeout=3  # timeout so the truck doesn't wait too long if a drone is unreachable
        )

        # Parse and print the drone's response
        data = response.json()
        if response.status_code == 200:
            print(f"[SUCCESS] Drone {drone_ip} responded: {data}")
        else:
            print(f"[FAIL] Drone {drone_ip} rejected: {data}")
            record_failed_attempt(drone_ip)

    except requests.RequestException as e:
        # Handle network errors such as timeouts
        print(f"[ERROR] Could not reach drone {drone_ip}: {e}")
        record_failed_attempt(drone_ip)

# Start of truck controller
if __name__ == "__main__":
    print("[STARTING] Truck authentication loop")

    # Run authentication in loop (stopped manually)
    while True:
        # Try to authenticate with each drone in the list
        for drone_ip in DRONE_IPS:
            authenticate_and_send_command(drone_ip)

        # Wait a few seconds before trying again
        print(f"[WAITING] Sleeping for {REAUTH_INTERVAL} seconds...\n")
        time.sleep(REAUTH_INTERVAL)

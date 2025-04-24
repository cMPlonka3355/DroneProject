import time
import requests
import hmac
import hashlib
import uuid

# Shared secret key used to sign authentication tokens
SECRET_KEY = b"supersecurekey"

# IP addresses of drones to authenticate
DRONE_IPS = ["192.168.56.105"]  # Update with your drone IP(s)

# Authentication and rate-limiting settings
REAUTH_INTERVAL = 10  # seconds between authentication attempts
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # 5 minutes

# Track failed attempts per drone IP
failed_attempts = {}

def generate_signed_token():
    """Generate a secure HMAC token using current time and a random UUID."""
    timestamp = int(time.time())
    randomizer = uuid.uuid4().hex
    base = f"{timestamp}:{randomizer}"
    token = hmac.new(SECRET_KEY, base.encode(), hashlib.sha256).hexdigest()
    return token, timestamp

def is_blocked(ip):
    """Check if the given IP is currently blocked due to repeated failures."""
    if ip in failed_attempts:
        info = failed_attempts[ip]
        if info["count"] >= MAX_ATTEMPTS:
            if time.time() < info["blocked_until"]:
                print(f"[BLOCKED] {ip} blocked until {time.ctime(info['blocked_until'])}")
                return True
            else:
                print(f"[UNBLOCKED] {ip}")
                failed_attempts[ip] = {"count": 0, "blocked_until": 0}
    return False

def record_failed_attempt(ip):
    """Increment the failed attempt count for a drone and block it if needed."""
    ip = ip.strip()
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 1, "blocked_until": 0}
    else:
        failed_attempts[ip]["count"] = failed_attempts[ip]["count"] + 1

    print(f"[RECORD] Count for {ip}: {failed_attempts[ip]['count']}")

    if failed_attempts[ip]["count"] >= MAX_ATTEMPTS and failed_attempts[ip]["blocked_until"] == 0:
        failed_attempts[ip]["blocked_until"] = time.time() + BLOCK_TIME
        print(f"[RECORD] {ip} is now blocked!")

def authenticate_and_send_command(ip):
    """Send an authentication request to a drone and track failures."""
    if is_blocked(ip):
        return

    token, timestamp = generate_signed_token()
    try:
        response = requests.post(
            f"http://{ip}:5000/command",
            json={"token": token, "timestamp": timestamp},
            headers={"Cache-Control": "no-cache"},
            timeout=3
        )

        print(f"[RESPONSE] {ip} returned {response.status_code}")
        if response.status_code != 200:
            record_failed_attempt(ip)
        else:
            print(f"[SUCCESS] {ip} accepted the request.")

    except Exception as e:
        print(f"[ERROR] Could not reach {ip}: {e}")
        record_failed_attempt(ip)

if __name__ == "__main__":
    print("[STARTING] Truck authentication loop...")
    while True:
        for ip in DRONE_IPS:
            authenticate_and_send_command(ip)

        print(f"[DEBUG] Failed Attempts State: {failed_attempts}")
        time.sleep(REAUTH_INTERVAL)

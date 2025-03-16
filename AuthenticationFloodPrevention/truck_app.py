import time  # Used to get the current time
import hmac  # Used for creating a secure token
import hashlib  # Provides hashing functions (SHA-256)
import requests  # Used to send HTTP requests to the drone

# Secret key shared ONLY between the truck and drones
SECRET_KEY = b"supersecurekey"

# Replace with the actual drone's IP address
DRONE_IP = "123.456.7.89"

def generate_token():
    """Generate a secure token for authentication attempts."""

    # Get the current time in seconds
    timestamp = int(time.time())

    # Create a hashed token using HMAC (Hash-based Message Authentication Code)
    token = hmac.new(SECRET_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()

    return token, timestamp

def authenticate_with_drone():
    """Send authentication request to a drone."""

    # Generate the authentication token
    token, timestamp = generate_token()

    # Send a POST request to the drone's authentication point
    response = requests.post(
        f"http://{DRONE_IP}:5000/authenticate",  # Drone's API URL
        json={"token": token, "timestamp": timestamp},  # Send token and timestamp as JSON data
    )

    # Print response of drone (success or failure)
    print("Drone Response:", response.json())

# If the script is run directly (not imported), authenticate with the drone
if __name__ == "__main__":
    authenticate_with_drone()
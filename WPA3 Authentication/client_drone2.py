import ssl, socket, time
from ssl import DER_cert_to_PEM_cert
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

SERVER_IP = "127.0.0.1"
PORT = 8443
KEY_PASSWORD = "drone2-pass"

def is_cert_expired(cert_dict):
    try:
        pem = DER_cert_to_PEM_cert(cert_dict['der'])
        cert = load_pem_x509_certificate(pem.encode(), default_backend())
        return cert.not_valid_after.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    except Exception:
        return True

def connect():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM")
    context.load_cert_chain("certs/drone2.crt", "certs/drone2.key", password=KEY_PASSWORD)
    context.load_verify_locations("certs/ca.crt")
    context.check_hostname = True

    with socket.create_connection((SERVER_IP, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="GroundControl") as tls:
            cert = tls.getpeercert(binary_form=False)
            cert['der'] = tls.getpeercert(binary_form=True)

            if is_cert_expired(cert):
                raise Exception("Server certificate is expired!")

            issuer_cn = next((x[0][1] for x in cert['issuer'] if x[0][0] == 'commonName'), None)
            if issuer_cn != "DroneCA":
                raise Exception("Untrusted certificate issuer.")

            server_cn = next((x[0][1] for x in cert['subject'] if x[0][0] == 'commonName'), None)
            if server_cn != "GroundControl":
                raise Exception("Unexpected server identity.")

            print("[DRONE2] Secure connection established.")
            print("[DRONE2] Server says:", tls.recv(1024).decode())

def try_connect_with_retries(retries=1, delay=2):
    for attempt in range(1, retries + 1):
        try:
            print(f"[DRONE2] Attempt {attempt} to connect...")
            connect()
            return
        except ConnectionRefusedError:
            print(f"[DRONE2] Server not available. Retrying in {delay} seconds.")
            time.sleep(delay)
        except Exception as e:
            print("[DRONE2 ERROR]", e)
            return
    print("[DRONE2] Failed to connect after retries.")

if __name__ == "__main__":
    try_connect_with_retries()

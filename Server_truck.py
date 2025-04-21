import ssl, socket, json, time
from datetime import datetime, timezone
from ssl import DER_cert_to_PEM_cert
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

TRUSTED_CLIENTS = {
    "UAV001": "telemetry"
}

ACCESS_POLICIES = {
    "telemetry": ["read_data"],
    "admin": ["read_data", "write_command"]
}

BLACKLIST = set()
REVOKED_SERIALS = {"00D2AB1C3E4F5"}  # Example revoked certificate serials

LOG_FILE = "access_log.json"
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_CERT = "certs/ca.crt"
KEY_PASSWORD = "server-pass"
SESSION_TIMEOUT = 30  # seconds

def log_access(cn, role, status, addr, serial=None):
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_cn": cn,
        "role": role,
        "status": status,
        "ip": addr[0],
        "serial": serial
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log) + "\n")

def is_cert_expired(cert_dict):
    try:
        pem = DER_cert_to_PEM_cert(cert_dict['der'])
        cert = load_pem_x509_certificate(pem.encode(), default_backend())
        return cert.not_valid_after.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    except Exception:
        return True

def is_blacklisted(cn):
    return cn in BLACKLIST

def is_action_authorized(role, action):
    return action in ACCESS_POLICIES.get(role, [])

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM")
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY, password=KEY_PASSWORD)
    context.load_verify_locations(CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 8443))
        sock.listen(5)
        print("[TRUCK] Secure Truck Server is running on port 8443...")

        while True:
            conn, addr = sock.accept()
            session_start = time.time()
            try:
                with context.wrap_socket(conn, server_side=True) as tls_conn:
                    cert = tls_conn.getpeercert(binary_form=False)
                    cert['der'] = tls_conn.getpeercert(binary_form=True)
                    cn = next((x[0][1] for x in cert['subject'] if x[0][0] == 'commonName'), None)
                    serial = cert.get('serialNumber')
                    issuer_cn = next((x[0][1] for x in cert['issuer'] if x[0][0] == 'commonName'), None)

                    if is_cert_expired(cert):
                        tls_conn.send(b"Certificate expired.")
                        log_access(cn or "unknown", "unknown", "expired", addr, serial)
                        return

                    if issuer_cn != "DroneCA":
                        tls_conn.send(b"Invalid certificate issuer.")
                        log_access(cn or "unknown", "unknown", "invalid_issuer", addr, serial)
                        return

                    if serial in REVOKED_SERIALS:
                        tls_conn.send(b"Certificate revoked.")
                        log_access(cn or "unknown", "unknown", "revoked", addr, serial)
                        return

                    if is_blacklisted(cn):
                        tls_conn.send(b"Access denied: you are blacklisted.")
                        log_access(cn, TRUSTED_CLIENTS.get(cn, "unknown"), "blacklisted", addr, serial)
                        return

                    if cn in TRUSTED_CLIENTS:
                        role = TRUSTED_CLIENTS[cn]
                        if not is_action_authorized(role, "read_data"):
                            tls_conn.send(b"Access denied: insufficient privileges.")
                            log_access(cn, role, "unauthorized", addr, serial)
                            return

                        if time.time() - session_start > SESSION_TIMEOUT:
                            tls_conn.send(b"Session expired.")
                            tls_conn.shutdown(socket.SHUT_RDWR)
                            tls_conn.close()
                            return

                        print(f"[+] Trusted drone '{cn}' connected.")
                        tls_conn.send(b"Welcome, authenticated drone.")
                        log_access(cn, role, "granted", addr, serial)
                    else:
                        print(f"[-] Unauthorized client '{cn}' attempted to connect.")
                        tls_conn.send(b"Access denied.")
                        log_access(cn or "unknown", "unknown", "denied", addr, serial)
            except ssl.SSLError as e:
                print(f"[SSL ERROR] {e}")

if __name__ == "__main__":
    start_server()

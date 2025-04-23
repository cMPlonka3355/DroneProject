from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, SubjectAlternativeName
from datetime import datetime, timedelta
import os


CERT_DIR = "certs"
os.makedirs(CERT_DIR, exist_ok=True)

def save_cert_and_key(cert, key, name, password=None):
    with open(f"{CERT_DIR}/{name}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())

    with open(f"{CERT_DIR}/{name}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ))

    # Save serial number for audit / revocation use
    with open(f"{CERT_DIR}/{name}.serial.txt", "w") as f:
        f.write(hex(cert.serial_number))

def create_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def create_self_signed_ca():
    key = create_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"DroneCA")
    ])
    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )\
        .sign(key, hashes.SHA256())
    save_cert_and_key(cert, key, "ca", password="ca-pass")
    return cert, key

def create_signed_cert(common_name, ca_cert, ca_key, filename, san_list=None, is_server=False, password=None):
    key = create_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    builder = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    if san_list:
        builder = builder.add_extension(
            SubjectAlternativeName([DNSName(name) for name in san_list]),
            critical=True
        )

    eku = ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([eku]),
        critical=False
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    cert = builder.sign(ca_key, hashes.SHA256())
    save_cert_and_key(cert, key, filename, password=password)

# Generate all certs
ca_cert, ca_key = create_self_signed_ca()
create_signed_cert("GroundControl", ca_cert, ca_key, "server", san_list=["GroundControl"], is_server=True, password="server-pass")
create_signed_cert("UAV001", ca_cert, ca_key, "drone", san_list=["UAV001"], is_server=False, password="drone-pass")
create_signed_cert("UAV002", ca_cert, ca_key, "drone2", san_list=["UAV002"], is_server=False, password="drone2-pass")
print("Certificates created in ./certs/")

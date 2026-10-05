"""本机 IPC 的自建 CA 与分离身份；无需软件发行证书或外部证书服务。"""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .common import canonical, require, write_new


def create(directory):
    directory = Path(directory)
    require(directory.is_absolute(), "ABSOLUTE_DIRECTORY_REQUIRED")
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HostGuard Local IPC")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
          .sign(ca_key, hashes.SHA256()))
    write_new(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    fingerprints = {}
    for role in ("server", "collector", "executor"):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                   .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == "server"
                                                        else ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        if role == "server":
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]), False)
        certificate = builder.sign(ca_key, hashes.SHA256())
        write_new(directory / (role + ".pem"), certificate.public_bytes(serialization.Encoding.PEM))
        write_new(directory / (role + ".key"), key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        fingerprints[role] = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    write_new(directory / "fingerprints.json", canonical(fingerprints))
    return fingerprints

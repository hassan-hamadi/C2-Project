#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for the C2 server.

Usage:
    python gen_cert.py --cn my-c2.example.com --san-ip 203.0.113.10
    python gen_cert.py --cn localhost                          # dev/local
    python gen_cert.py --cn c2.local --san-dns c2.local --san-ip 10.0.0.5 --days 730

Writes server.crt and server.key into the certs/ directory next to this file.
Also prints the SPKI SHA-256 pin that gets baked into agent binaries at build time.
"""

import argparse
import datetime
import hashlib
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def generate_certificate(cn: str, san_ips: list[str], san_dns: list[str], days: int):
    """Generate an RSA-2048 key and self-signed X.509 certificate."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    san_entries: list[x509.GeneralName] = []
    for dns_name in san_dns:
        san_entries.append(x509.DNSName(dns_name))
    for ip_str in san_ips:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    # Modern TLS clients check SANs, not the CN, so always include the CN here too.
    if cn not in san_dns:
        san_entries.insert(0, x509.DNSName(cn))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    return key, cert


def compute_spki_pin(cert: x509.Certificate) -> str:
    """Return the SHA-256 hex digest of the certificate's SubjectPublicKeyInfo (DER)."""
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Generate a self-signed TLS certificate for the C2 server.")
    parser.add_argument("--cn", default="localhost", help="Common Name (default: localhost)")
    parser.add_argument("--san-ip", action="append", default=[], help="IP address to add as a SAN (repeatable)")
    parser.add_argument("--san-dns", action="append", default=[], help="DNS name to add as a SAN (repeatable)")
    parser.add_argument("--days", type=int, default=365, help="Certificate validity in days (default: 365)")
    args = parser.parse_args()

    os.makedirs(CERTS_DIR, exist_ok=True)

    key_path = os.path.join(CERTS_DIR, "server.key")
    cert_path = os.path.join(CERTS_DIR, "server.crt")

    if os.path.exists(cert_path) or os.path.exists(key_path):
        print("[!] Existing certificate files will be overwritten.")

    key, cert = generate_certificate(args.cn, args.san_ip, args.san_dns, args.days)

    # Write private key with restrictive permissions so other users on the system can't read it.
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # chmod is a no-op on Windows, safe to ignore

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    pin = compute_spki_pin(cert)
    print()
    print("=======================================")
    print("  TLS Certificate Generated")
    print("=======================================")
    print(f"  CN        : {args.cn}")
    print(f"  SAN IPs   : {', '.join(args.san_ip) or '(none)'}")
    print(f"  SAN DNS   : {', '.join(args.san_dns) or '(none)'}")
    print(f"  Valid for  : {args.days} days")
    print(f"  Cert file  : {cert_path}")
    print(f"  Key file   : {key_path}")
    print(f"  SPKI Pin   : {pin}")
    print("=======================================")
    print()


if __name__ == "__main__":
    main()

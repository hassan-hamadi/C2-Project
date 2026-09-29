#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for the C2 server.

Usage:
    python gen_cert.py --cn my-c2.example.com --san-ip 203.0.113.10
    python gen_cert.py --cn localhost                          # dev/local
    python gen_cert.py --cn c2.local --san-dns c2.local --san-ip 10.0.0.5 --days 730

Atomically writes server.pem into the certs/ directory next to this file.
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
if __package__:
    from .certificate_storage import publish_certificate_bundle
else:
    from certificate_storage import publish_certificate_bundle


CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def generate_certificate(cn: str, san_ips: list[str], san_dns: list[str], days: int):
    """Generate an RSA-2048 key and self-signed X.509 certificate."""

    if not cn.strip() or not 1 <= days <= 3650:
        raise ValueError("cn must be nonempty and days must be between 1 and 3650")
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    san_entries: list[x509.GeneralName] = []
    for dns_name in san_dns:
        san_entries.append(x509.DNSName(dns_name))
    for ip_str in san_ips:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    # Modern TLS clients check SANs, not the CN, so always include the CN here too.
    if cn not in san_dns:
        san_entries.insert(0, x509.DNSName(cn))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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

    bundle_path = os.path.join(CERTS_DIR, "server.pem")
    if any(os.path.exists(os.path.join(CERTS_DIR, name)) for name in ("server.pem", "server.crt", "server.key")):
        print("[!] The active certificate will be replaced by server.pem.")

    key, cert = generate_certificate(args.cn, args.san_ip, args.san_dns, args.days)

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    publish_certificate_bundle(CERTS_DIR, cert_pem, key_pem)

    pin = compute_spki_pin(cert)
    print()
    print("=======================================")
    print("  TLS Certificate Generated")
    print("=======================================")
    print(f"  CN        : {args.cn}")
    print(f"  SAN IPs   : {', '.join(args.san_ip) or '(none)'}")
    print(f"  SAN DNS   : {', '.join(args.san_dns) or '(none)'}")
    print(f"  Valid for  : {args.days} days")
    print(f"  PEM bundle : {bundle_path}")
    print(f"  SPKI Pin   : {pin}")
    print("=======================================")
    print("Restart the server to load this certificate.")
    print()


if __name__ == "__main__":
    main()

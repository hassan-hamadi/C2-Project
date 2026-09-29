"""Restricted certificate-record sizing for public TLS sites."""

import ipaddress
import re
import socket
import ssl
import time


class ProbeInputError(ValueError):
    pass


class ProbeDenied(PermissionError):
    pass


REALITY_CERTIFICATE_LIMIT_BYTES = 8192


def canonical_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ProbeInputError("Domain must be a non-empty hostname string.")
    try:
        domain = value.strip().removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProbeInputError("Invalid domain name.") from exc
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 253 or not re.fullmatch(rf"{label}(?:\.{label})*", domain):
        raise ProbeInputError("Enter a hostname without a scheme, path, or port.")
    return domain


def measure_certificate_record(domain):
    """Estimate the TLS 1.3 Certificate record size for a public hostname.

    All resolved addresses must be public, and connections use those validated
    addresses without resolving the name again.
    """
    domain = canonical_domain(domain)
    addresses = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not addresses:
        raise OSError("No addresses returned for this domain.")
    for family, _, _, _, address in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ProbeDenied("Unsupported address family.")
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast:
            raise ProbeDenied("Certificate measurement does not allow private or reserved destinations.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    deadline = time.monotonic() + 10
    last_error = None
    for family, kind, protocol, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Certificate measurement timed out.")
        try:
            with socket.socket(family, kind, protocol) as connection:
                connection.settimeout(remaining)
                connection.connect(address)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Certificate measurement timed out.")
                connection.settimeout(remaining)
                with context.wrap_socket(connection, server_hostname=domain) as tls_connection:
                    chain = tls_connection.get_unverified_chain()
                    if not chain or any(not isinstance(cert, bytes) or not cert for cert in chain):
                        raise OSError("The server did not provide a usable certificate chain.")

                    # TLS 1.3 Certificate message:
                    #   handshake header (4), request context (1), list length (3),
                    #   and per-certificate DER length (3) plus extensions length (2).
                    # The encrypted record adds its header (5), inner content type (1),
                    # and the TLS 1.3 AEAD tag (16). Certificate-entry extensions and
                    # record padding are uncommon and intentionally excluded.
                    return 30 + sum(5 + len(cert) for cert in chain)
        except OSError as exc:
            last_error = exc
    raise last_error

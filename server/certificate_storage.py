"""Publish a matching TLS certificate and key with one filesystem replacement."""

import logging
import os
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def publish_certificate_bundle(certs_dir, cert_pem, key_pem):
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("Certificate and key do not match")

    os.makedirs(certs_dir, mode=0o700, exist_ok=True)
    bundle_path = os.path.join(certs_dir, "server.pem")
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".server-pair-", dir=certs_dir)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(cert_pem + key_pem)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, bundle_path)
        temp_path = None
        # Publication has already succeeded. A directory-sync failure affects
        # crash durability, not which pair is now selected.
        try:
            dir_fd = os.open(certs_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            logging.getLogger(__name__).warning("Certificate bundle switched, but directory fsync failed")
    finally:
        if temp_path is not None:
            os.unlink(temp_path)
    return bundle_path

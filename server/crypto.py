"""
AES-256-GCM payload encryption helpers for the C2 team server.

All C2 traffic (checkin, tasks, results) is encrypted with a per-build
pre-shared key. The key is generated at build time, injected into the
agent binary as a compile-time constant, and stored in the builds table
so the server can look it up via the key_id fingerprint that the agent
includes in every request.

Wire format for every encrypted envelope:
    {
        "kid":  "<8-char hex key fingerprint>",
        "data": "<base64(nonce[12] + ciphertext + gcm_tag[16])>"
    }

The kid field is not secret, it is just a lookup token.
The 32-byte AES key stored in encryption_key IS secret.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> tuple[str, str]:
    """
    Generate a fresh AES-256 key for a new agent build.

    Returns:
        (key_hex, key_id) where:
            key_hex  -- 64-char hex string (32 raw bytes), the secret baked into the binary
            key_id   -- 8-char hex string, non-secret SHA-256 fingerprint for server-side lookup
    """
    key_bytes = os.urandom(32)
    key_hex   = key_bytes.hex()
    key_id    = hashlib.sha256(key_bytes).hexdigest()[:8]
    return key_hex, key_id


def encrypt_payload(key_hex: str, plaintext: bytes) -> str:
    """
    AES-256-GCM encrypt plaintext.

    Args:
        key_hex:   64-char hex string (32-byte AES key)
        plaintext: raw bytes to encrypt (typically JSON-encoded payload)

    Returns:
        base64-encoded string: nonce[12] + ciphertext + gcm_tag[16]
        The GCM tag is appended automatically by AESGCM.encrypt().
    """
    key   = bytes.fromhex(key_hex)
    nonce = os.urandom(12)                               # 96-bit nonce, random per message
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)   # no AAD
    return base64.b64encode(nonce + ct).decode()


def decrypt_payload(key_hex: str, encoded: str) -> bytes:
    """
    AES-256-GCM decrypt an encrypted payload.

    Args:
        key_hex: 64-char hex string (32-byte AES key)
        encoded: base64-encoded string from encrypt_payload()

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: if the auth tag does not match
        (tampered ciphertext, wrong key, or corrupted data).
    """
    key        = bytes.fromhex(key_hex)
    raw        = base64.b64decode(encoded)
    nonce, ct  = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)

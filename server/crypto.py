# AES-256-GCM helpers for C2 traffic encryption.
# Each build gets a fresh key baked into the binary at compile time.
# The server looks it up via the kid fingerprint the agent includes in every request.
# Wire format: {"kid": "<8-char fingerprint>", "data": "<base64(nonce + ciphertext + tag)>"}

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> tuple[str, str]:
    """
    Generate a fresh AES-256 key for a new build.
    Returns (key_hex, key_id): key_hex is the secret baked into the binary,
    key_id is a short SHA-256 fingerprint used to look it up server-side.
    """
    key_bytes = os.urandom(32)
    key_hex   = key_bytes.hex()
    key_id    = hashlib.sha256(key_bytes).hexdigest()[:8]
    return key_hex, key_id


def encrypt_payload(key_hex: str, plaintext: bytes) -> str:
    """Encrypt plaintext with AES-256-GCM. Returns base64(nonce[12] + ciphertext + gcm_tag[16])."""
    key   = bytes.fromhex(key_hex)
    nonce = os.urandom(12)                               # 96-bit nonce, random per message
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)   # no AAD
    return base64.b64encode(nonce + ct).decode()


def decrypt_payload(key_hex: str, encoded: str) -> bytes:
    """
    Decrypt a payload from encrypt_payload().
    Raises InvalidTag if the auth tag fails (wrong key or tampered data).
    """
    key        = bytes.fromhex(key_hex)
    raw        = base64.b64decode(encoded)
    nonce, ct  = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)

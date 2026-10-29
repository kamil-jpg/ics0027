"""Cryptographic engine: AES-256-GCM data encryption and Argon2id key derivation."""
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# Argon2id KDF parameters (time_cost, memory_cost in KiB, parallelism)
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_key() -> bytes:
    """Generate a random 256-bit key, e.g. a per-user master key."""
    return os.urandom(KEY_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and salt using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=KDF_TIME_COST,
        memory_cost=KDF_MEMORY_COST,
        parallelism=KDF_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises InvalidTag on tampering or wrong key."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

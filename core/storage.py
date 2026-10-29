"""Encrypted file storage on disk, and safe path/filename handling."""
import os
import re
import uuid

STORAGE_DIR = os.environ.get("SECFILE_STORAGE_DIR", os.path.join(os.getcwd(), "data", "encrypted"))
os.makedirs(STORAGE_DIR, exist_ok=True)

# Allow only a conservative set of characters in a user-supplied display name.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")


class InvalidFileNameError(ValueError):
    pass


def sanitize_display_name(name: str) -> str:
    """Validate a user-supplied file name; reject path separators and traversal."""
    base = os.path.basename(name or "")
    if base != name:
        raise InvalidFileNameError("File name must not contain path separators.")
    if base in ("", ".", "..") or not _SAFE_NAME_RE.match(base):
        raise InvalidFileNameError("File name contains invalid characters.")
    return base


def new_storage_name() -> str:
    """Generate a random, non-guessable name for the on-disk encrypted blob."""
    return uuid.uuid4().hex


def storage_path(storage_name: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", storage_name):
        raise InvalidFileNameError("Invalid storage identifier.")
    return os.path.join(STORAGE_DIR, storage_name)


def save_encrypted(storage_name: str, ciphertext: bytes) -> None:
    path = storage_path(storage_name)
    with open(path, "wb") as f:
        f.write(ciphertext)


def load_encrypted(storage_name: str) -> bytes:
    path = storage_path(storage_name)
    with open(path, "rb") as f:
        return f.read()


def delete_encrypted(storage_name: str) -> None:
    path = storage_path(storage_name)
    if os.path.exists(path):
        os.remove(path)


def secure_delete_path(path: str) -> None:
    """Best-effort secure delete: overwrite the file with zeros before removing it."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    length = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(b"\x00" * length)
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)

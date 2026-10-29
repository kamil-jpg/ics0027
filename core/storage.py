"""Encrypted file storage on disk, and safe path/filename handling."""
import os
import re
import uuid

STORAGE_DIR = os.environ.get("SECFILE_STORAGE_DIR", os.path.join(os.getcwd(), "data", "encrypted"))
os.makedirs(STORAGE_DIR, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024  # bytes; files are encrypted in memory, so cap them

# Allow only a conservative set of characters in a user-supplied display name.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")


class InvalidFileNameError(ValueError):
    pass


class InvalidPathError(ValueError):
    pass


class FileTooLargeError(ValueError):
    pass


def sanitize_display_name(name: str) -> str:
    """Validate a user-supplied file name; reject path separators and traversal."""
    base = os.path.basename(name or "")
    if base != name:
        raise InvalidFileNameError("File name must not contain path separators.")
    if base in ("", ".", "..") or not _SAFE_NAME_RE.match(base):
        raise InvalidFileNameError("File name contains invalid characters.")
    return base


def sanitize_upload_name(name: str) -> str:
    """Turn an untrusted client-supplied file name into a safe display name."""
    base = re.split(r"[\\/]", name or "")[-1].strip()
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:255]
    if base in ("", ".", ".."):
        raise InvalidFileNameError("File name is empty or invalid.")
    return base


def check_input_file(path: str) -> str:
    """Validate a path the user wants to read: must be a regular, readable file within the size limit."""
    if not path or "\x00" in path:
        raise InvalidPathError("Invalid input path.")
    if not os.path.isfile(path):
        raise InvalidPathError(f"Input file not found or not a regular file: {path}")
    if not os.access(path, os.R_OK):
        raise InvalidPathError(f"Input file is not readable: {path}")
    if os.path.getsize(path) > MAX_FILE_SIZE:
        raise FileTooLargeError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MiB limit.")
    return path


def check_output_file(path: str, overwrite: bool = False) -> str:
    """Validate a path the user wants to write: parent must exist and the target must not be clobbered silently."""
    if not path or "\x00" in path:
        raise InvalidPathError("Invalid output path.")
    if os.path.isdir(path):
        raise InvalidPathError(f"Output path is a directory: {path}")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise InvalidPathError(f"Output directory does not exist: {parent}")
    if not os.access(parent, os.W_OK):
        raise InvalidPathError(f"Output directory is not writable: {parent}")
    if os.path.lexists(path) and not overwrite:
        raise InvalidPathError(f"Output file already exists (use --force to overwrite): {path}")
    return path


def write_private_file(path: str, data: bytes) -> None:
    """Write data to path with owner-only permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def new_storage_name() -> str:
    """Generate a random, non-guessable name for the on-disk encrypted blob."""
    return uuid.uuid4().hex


def storage_path(storage_name: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", storage_name):
        raise InvalidFileNameError("Invalid storage identifier.")
    return os.path.join(STORAGE_DIR, storage_name)


def save_encrypted(storage_name: str, ciphertext: bytes) -> None:
    write_private_file(storage_path(storage_name), ciphertext)


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

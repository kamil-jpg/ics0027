"""Encrypted file storage on disk, and safe path/filename handling."""
import os
import re
import stat
import unicodedata
import uuid
from contextlib import contextmanager

STORAGE_DIR = os.environ.get("SECFILE_STORAGE_DIR", os.path.join(os.getcwd(), "data", "encrypted"))
os.makedirs(STORAGE_DIR, mode=0o700, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024  # bytes; files are encrypted in memory, so cap them
UPLOAD_EXTENSIONS = frozenset({".txt", ".md", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg", ".zip", ".bin"})

# Allow only a conservative set of characters in a user-supplied display name.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")


class InvalidFileNameError(ValueError):
    pass


class InvalidPathError(ValueError):
    pass


class FileTooLargeError(ValueError):
    pass


def validate_local_path(path: str) -> None:
    if (not path or ".." in path.split(os.sep)
            or any(unicodedata.category(char) == "Cc" for char in path)):
        raise InvalidPathError("Invalid local path.")


@contextmanager
def _parent_directory(path: str):
    """Pin each parent directory without following symlinks or '..' components."""
    validate_local_path(path)
    parent, name = os.path.split(path)
    if name in {"", ".", ".."}:
        raise InvalidPathError("Invalid local path.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(os.sep if os.path.isabs(path) else ".", flags)
    try:
        for part in parent.split(os.sep):
            if part in {"", "."}:
                continue
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, name
    finally:
        os.close(fd)


def validate_upload_type(name: str) -> None:
    # Extension policy only: uploaded bytes remain opaque and are never executed,
    # extracted, parsed or served inline. A browser-supplied MIME type is untrusted.
    if os.path.splitext(name)[1].lower() not in UPLOAD_EXTENSIONS:
        raise InvalidFileNameError("This file type is not allowed.")


def sanitize_display_name(name: str) -> str:
    """Validate a user-supplied file name; reject path separators and traversal."""
    base = os.path.basename(name or "")
    if base != name:
        raise InvalidFileNameError("File name must not contain path separators.")
    if base in ("", ".", "..") or not _SAFE_NAME_RE.fullmatch(base):
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
    validate_local_path(path)
    if not os.path.isfile(path):
        raise InvalidPathError(f"Input file not found or not a regular file: {path}")
    if not os.access(path, os.R_OK):
        raise InvalidPathError(f"Input file is not readable: {path}")
    if os.path.getsize(path) > MAX_FILE_SIZE:
        raise FileTooLargeError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MiB limit.")
    return path


def open_input_file(path: str):
    """Open and validate the same file descriptor that will actually be read."""
    with _parent_directory(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InvalidPathError("Input must be a regular file.")
        if info.st_size > MAX_FILE_SIZE:
            raise FileTooLargeError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MiB limit.")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def check_output_file(path: str, overwrite: bool = False) -> str:
    """Validate a path the user wants to write: parent must exist and the target must not be clobbered silently."""
    validate_local_path(path)
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


def write_private_file(path: str, data: bytes, overwrite: bool = False) -> None:
    """Write data to path with owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    if not overwrite:
        flags |= os.O_EXCL
    with _parent_directory(path) as (parent, name):
        fd = os.open(name, flags, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InvalidPathError("Output must be a regular file without hard links.")
        os.fchmod(f.fileno(), 0o600)
        os.ftruncate(f.fileno(), 0)
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
    with _parent_directory(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or not 16 <= info.st_size <= MAX_FILE_SIZE + 16:
            raise InvalidPathError("Invalid encrypted file.")
        data = f.read(MAX_FILE_SIZE + 17)
        if len(data) > MAX_FILE_SIZE + 16:
            raise InvalidPathError("Invalid encrypted file.")
        return data


def delete_encrypted(storage_name: str) -> None:
    path = storage_path(storage_name)
    secure_delete_path(path)


def secure_delete_path(path: str) -> None:
    """Best-effort secure delete: overwrite the file with zeros before removing it."""
    with _parent_directory(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "r+b") as f:
            _wipe_and_unlink(f, parent, name)


def _wipe_and_unlink(f, parent: int, name: str) -> None:
    info = os.fstat(f.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InvalidPathError("Not a regular file without hard links.")
    remaining = info.st_size
    block = b"\x00" * (1024 * 1024)
    while remaining:
        size = min(remaining, len(block))
        f.write(block[:size])
        remaining -= size
    f.flush()
    os.fsync(f.fileno())
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
        raise InvalidPathError("File changed during deletion.")
    os.remove(name, dir_fd=parent)
    os.fsync(parent)

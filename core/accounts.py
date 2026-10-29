"""Shared account logic used by both the CLI and web interfaces."""
import re

from sqlalchemy.orm import Session as DbSession

from core import auth, crypto
from core.db import User


USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128  # bounds Argon2 work an attacker can force per request


class AuthenticationError(Exception):
    pass


class UsernameTakenError(Exception):
    pass


def register_user(db: DbSession, username: str, password: str) -> User:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.")
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        raise ValueError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.")
    if db.query(User).filter(User.username == username).first() is not None:
        raise UsernameTakenError("Username is already taken.")

    salt = crypto.generate_salt()
    kek = crypto.derive_key(password, salt)  # key-encryption-key from the password
    master_key = crypto.generate_key()
    nonce, wrapped = crypto.encrypt_bytes(kek, master_key)

    user = User(
        username=username,
        password_hash=auth.hash_password(password),
        kdf_salt=salt,
        wrapped_master_key=wrapped,
        wrapped_master_key_nonce=nonce,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_and_unlock(db: DbSession, username: str, password: str) -> tuple[User, bytes]:
    """Verify credentials and return (user, master_key). Raises AuthenticationError on failure."""
    if len(password) > MAX_PASSWORD_LEN:
        raise AuthenticationError("Invalid username or password.")
    user = db.query(User).filter(User.username == username.strip()).first()
    if user is None:
        auth.verify_password(auth.DUMMY_HASH, password)  # equalise timing to hide user existence
        raise AuthenticationError("Invalid username or password.")
    if not auth.verify_password(user.password_hash, password):
        raise AuthenticationError("Invalid username or password.")

    kek = crypto.derive_key(password, user.kdf_salt)
    try:
        master_key = crypto.decrypt_bytes(kek, user.wrapped_master_key_nonce, user.wrapped_master_key)
    except Exception as exc:  # tampered/corrupt vault entry
        raise AuthenticationError("Failed to unlock account vault.") from exc
    return user, master_key

"""Shared account logic used by both the CLI and web interfaces."""
import re

from sqlalchemy.orm import Session as DbSession
from sqlalchemy.exc import IntegrityError
from cryptography.exceptions import InvalidTag

from core import auth, crypto
from core.db import User
from core.security import audit, secure_wipe


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
        audit("registration", "failure")
        raise ValueError("Username must be 1-64 characters: letters, digits, '.', '_' or '-'.")
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        audit("registration", "failure")
        raise ValueError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.")
    if db.query(User).filter(User.username == username).first() is not None:
        audit("registration", "failure")
        raise UsernameTakenError("Username is already taken.")

    salt = crypto.generate_salt()
    kek = bytearray(crypto.derive_key(password, salt))
    master_key = bytearray(crypto.generate_key())
    try:
        nonce, wrapped = crypto.encrypt_bytes(kek, bytes(master_key))
        user = User(
            username=username,
            password_hash=auth.hash_password(password),
            kdf_salt=salt,
            wrapped_master_key=wrapped,
            wrapped_master_key_nonce=nonce,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if db.query(User).filter(User.username == username).first() is not None:
                audit("registration", "failure")
                raise UsernameTakenError("Username is already taken.") from exc
            raise
    finally:
        secure_wipe(kek)
        secure_wipe(master_key)
    db.refresh(user)
    audit("registration", "success", user.id)
    return user


def authenticate_and_unlock(db: DbSession, username: str, password: str) -> tuple[User, bytearray]:
    """Verify credentials and return (user, master_key). Raises AuthenticationError on failure."""
    if len(password) > MAX_PASSWORD_LEN or not USERNAME_RE.fullmatch(username.strip()):
        audit("authentication", "failure")
        raise AuthenticationError("Invalid username or password.")
    user = db.query(User).filter(User.username == username.strip()).first()
    if user is None:
        auth.verify_password(auth.DUMMY_HASH, password)  # equalise timing to hide user existence
        audit("authentication", "failure")
        raise AuthenticationError("Invalid username or password.")
    if not auth.verify_password(user.password_hash, password):
        audit("authentication", "failure")
        raise AuthenticationError("Invalid username or password.")

    kek = bytearray(crypto.derive_key(password, user.kdf_salt))
    try:
        master_key = bytearray(crypto.decrypt_bytes(kek, user.wrapped_master_key_nonce, user.wrapped_master_key))
    except InvalidTag as exc:
        audit("authentication", "failure")
        raise AuthenticationError("Invalid username or password.") from exc
    finally:
        secure_wipe(kek)
    audit("authentication", "success", user.id)
    return user, master_key

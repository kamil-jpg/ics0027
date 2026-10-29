"""Server-side web session management: creation, validation, and in-memory master-key cache."""
import datetime
import secrets

from sqlalchemy.orm import Session as DbSession

from core.db import WebSession
from core.security import secure_wipe

IDLE_TIMEOUT = datetime.timedelta(minutes=15)
ABSOLUTE_TIMEOUT = datetime.timedelta(hours=12)

# Master keys never touch the database or the cookie; they live only in this
# process-local cache for the lifetime of the session, and are wiped on logout/expiry.
_master_key_cache: dict[str, bytearray] = {}


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def create_session(db: DbSession, user_id: int, master_key: bytes) -> tuple[str, str]:
    """Create a new session row and return (session_token, csrf_token)."""
    purge_expired(db)
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = _now()
    row = WebSession(
        session_token=session_token,
        csrf_token=csrf_token,
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + ABSOLUTE_TIMEOUT,
    )
    db.add(row)
    db.commit()
    _master_key_cache[session_token] = bytearray(master_key)
    return session_token, csrf_token


def _is_expired(row: WebSession, now: datetime.datetime) -> bool:
    return row.expires_at < now or now - row.last_seen_at > IDLE_TIMEOUT


def get_session(db: DbSession, session_token: str) -> WebSession | None:
    """Return the live session for a token, sliding the idle timeout; destroy it if expired."""
    if not session_token:
        return None
    row = db.query(WebSession).filter(WebSession.session_token == session_token).first()
    if row is None:
        return None
    now = _now()
    if _is_expired(row, now):
        destroy_session(db, session_token)
        return None
    row.last_seen_at = now
    db.commit()
    return row


def purge_expired(db: DbSession) -> None:
    now = _now()
    for row in db.query(WebSession).all():
        if _is_expired(row, now):
            destroy_session(db, row.session_token)


def get_master_key(session_token: str) -> bytes | None:
    key = _master_key_cache.get(session_token)
    return bytes(key) if key is not None else None


def destroy_session(db: DbSession, session_token: str) -> None:
    row = db.query(WebSession).filter(WebSession.session_token == session_token).first()
    if row is not None:
        db.delete(row)
        db.commit()
    key = _master_key_cache.pop(session_token, None)
    if key is not None:
        secure_wipe(key)

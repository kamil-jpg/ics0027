"""Server-side web session management: creation, validation, and in-memory master-key cache."""
import datetime
import secrets

from sqlalchemy.orm import Session as DbSession

from core.db import WebSession

SESSION_TTL = datetime.timedelta(minutes=30)

# Master keys never touch the database or the cookie; they live only in this
# process-local cache for the lifetime of the session, and are wiped on logout/expiry.
_master_key_cache: dict[str, bytes] = {}


def create_session(db: DbSession, user_id: int, master_key: bytes) -> tuple[str, str]:
    """Create a new session row and return (session_token, csrf_token)."""
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + SESSION_TTL
    row = WebSession(
        session_token=session_token, csrf_token=csrf_token, user_id=user_id, expires_at=expires_at
    )
    db.add(row)
    db.commit()
    _master_key_cache[session_token] = master_key
    return session_token, csrf_token


def get_session(db: DbSession, session_token: str) -> WebSession | None:
    if not session_token:
        return None
    row = db.query(WebSession).filter(WebSession.session_token == session_token).first()
    if row is None:
        return None
    if row.expires_at < datetime.datetime.utcnow():
        destroy_session(db, session_token)
        return None
    return row


def get_master_key(session_token: str) -> bytes | None:
    return _master_key_cache.get(session_token)


def destroy_session(db: DbSession, session_token: str) -> None:
    row = db.query(WebSession).filter(WebSession.session_token == session_token).first()
    if row is not None:
        db.delete(row)
        db.commit()
    _master_key_cache.pop(session_token, None)

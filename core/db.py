"""Database models and session factory (SQLite via SQLAlchemy ORM)."""
import datetime
import os

from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String, create_engine, event
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATA_DIR = os.environ.get("SECFILE_DATA_DIR", os.path.join(os.getcwd(), "data"))
os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "secfile.db")
_db_fd = os.open(DB_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
try:
    os.fchmod(_db_fd, 0o600)
finally:
    os.close(_db_fd)

# check_same_thread=False is required for FastAPI's threaded request handling;
# each request still gets its own Session via get_db().
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _enable_foreign_keys(connection, _record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


def utc_now() -> datetime.datetime:
    """SQLite stores naive timestamps; their timezone is always UTC."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    kdf_salt = Column(LargeBinary, nullable=False)
    # The per-user master key, encrypted with a key derived from the login password.
    wrapped_master_key = Column(LargeBinary, nullable=False)
    wrapped_master_key_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utc_now)

    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    storage_name = Column(String(64), unique=True, nullable=False)  # random UUID on disk
    original_name = Column(String(255), nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=utc_now)

    owner = relationship("User", back_populates="files")


class WebSession(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    session_token = Column(String(128), unique=True, nullable=False, index=True)
    csrf_token = Column(String(128), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utc_now)
    expires_at = Column(DateTime, nullable=False)  # absolute expiry
    last_seen_at = Column(DateTime, nullable=False, default=utc_now)  # idle timeout


def init_db() -> None:
    Base.metadata.create_all(engine)


def reset_sessions() -> None:
    """Drop and recreate the web sessions table.

    Session master keys live only in process memory, so sessions cannot survive a
    server restart anyway; this also keeps the schema current.
    """
    WebSession.__table__.drop(engine, checkfirst=True)
    WebSession.__table__.create(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

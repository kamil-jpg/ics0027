"""Database models and session factory (SQLite via SQLAlchemy ORM)."""
import datetime
import os

from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATA_DIR = os.environ.get("SECFILE_DATA_DIR", os.path.join(os.getcwd(), "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "secfile.db")

# check_same_thread=False is required for FastAPI's threaded request handling;
# each request still gets its own Session via get_db().
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    kdf_salt = Column(LargeBinary, nullable=False)
    # The per-user master key, encrypted with a key derived from the login password.
    wrapped_master_key = Column(LargeBinary, nullable=False)
    wrapped_master_key_nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    storage_name = Column(String(64), unique=True, nullable=False)  # random UUID on disk
    original_name = Column(String(255), nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="files")


class WebSession(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    session_token = Column(String(128), unique=True, nullable=False, index=True)
    csrf_token = Column(String(128), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

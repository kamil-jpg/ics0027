"""Shared file operations: encrypt+store and load+decrypt, used by both interfaces."""
import os
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sqlalchemy.orm import Session as DbSession

from core import crypto, storage
from core.db import FileRecord
from core.security import audit, secure_wipe


def store_file(db: DbSession, user_id: int, master_key: bytes | bytearray, display_name: str, plaintext: bytes) -> FileRecord:
    display_name = storage.sanitize_display_name(display_name)
    if len(plaintext) > storage.MAX_FILE_SIZE:
        raise storage.FileTooLargeError(
            f"File exceeds the {storage.MAX_FILE_SIZE // (1024 * 1024)} MiB limit."
        )
    storage_name = storage.new_storage_name()
    # Binding the storage name as AAD stops encrypted blobs being swapped between records.
    nonce, ciphertext = crypto.encrypt_bytes(master_key, plaintext, storage_name.encode())
    storage.save_encrypted(storage_name, ciphertext)
    record = FileRecord(user_id=user_id, storage_name=storage_name, original_name=display_name, nonce=nonce)
    db.add(record)
    try:
        db.commit()
    except Exception:
        db.rollback()
        storage.delete_encrypted(storage_name)
        raise
    db.refresh(record)
    audit("file_encrypt", "success", user_id)
    return record


def store_file_stream(
    db: DbSession, user_id: int, master_key: bytes | bytearray, display_name: str, source: BinaryIO
) -> FileRecord:
    """Encrypt in bounded chunks using the same ciphertext-and-tag format as AESGCM."""
    display_name = storage.sanitize_display_name(display_name)
    storage_name = storage.new_storage_name()
    path = storage.storage_path(storage_name)
    nonce = os.urandom(crypto.NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(master_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(storage_name.encode())
    with storage._parent_directory(path) as (parent, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    chunk = bytearray(1024 * 1024)
    try:
        with os.fdopen(fd, "wb") as target:
            total = 0
            while True:
                if hasattr(source, "readinto"):
                    count = source.readinto(chunk)
                else:
                    data = source.read(len(chunk))
                    count = len(data)
                    chunk[:count] = data
                    del data
                if not count:
                    break
                total += count
                if total > storage.MAX_FILE_SIZE:
                    raise storage.FileTooLargeError(
                        f"File exceeds the {storage.MAX_FILE_SIZE // (1024 * 1024)} MiB limit."
                    )
                target.write(encryptor.update(memoryview(chunk)[:count]))
            target.write(encryptor.finalize())
            target.write(encryptor.tag)
        record = FileRecord(user_id=user_id, storage_name=storage_name, original_name=display_name, nonce=nonce)
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()
        storage.delete_encrypted(storage_name)
        raise
    finally:
        secure_wipe(chunk)
    db.refresh(record)
    audit("file_encrypt", "success", user_id)
    return record


def owned_file(db: DbSession, user_id: int, file_id: int) -> FileRecord | None:
    return db.query(FileRecord).filter(FileRecord.id == file_id, FileRecord.user_id == user_id).first()


def read_file(db: DbSession, user_id: int, file_id: int, master_key: bytes | bytearray) -> bytes:
    """Decrypt a stored file. Raises FileNotFoundError or cryptography InvalidTag."""
    record = owned_file(db, user_id, file_id)
    if record is None:
        audit("file_decrypt", "denied", user_id)
        raise FileNotFoundError("File not found.")
    ciphertext = storage.load_encrypted(record.storage_name)
    plaintext = crypto.decrypt_bytes(master_key, record.nonce, ciphertext, record.storage_name.encode())
    audit("file_decrypt", "success", user_id)
    return plaintext


def remove_file(db: DbSession, user_id: int, file_id: int) -> None:
    record = owned_file(db, user_id, file_id)
    if record is None:
        audit("file_delete", "denied", user_id)
        raise FileNotFoundError("File not found.")
    storage.delete_encrypted(record.storage_name)
    db.delete(record)
    db.commit()
    audit("file_delete", "success", user_id)

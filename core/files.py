"""Shared file-vault operations: encrypt+store and load+decrypt, used by both interfaces."""
from sqlalchemy.orm import Session as DbSession

from core import crypto, storage
from core.db import FileRecord


def store_file(db: DbSession, user_id: int, master_key: bytes, display_name: str, plaintext: bytes) -> FileRecord:
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
    db.commit()
    db.refresh(record)
    return record


def read_file(record: FileRecord, master_key: bytes) -> bytes:
    """Decrypt a stored file. Raises FileNotFoundError or cryptography InvalidTag."""
    ciphertext = storage.load_encrypted(record.storage_name)
    return crypto.decrypt_bytes(master_key, record.nonce, ciphertext, record.storage_name.encode())


def remove_file(db: DbSession, record: FileRecord) -> None:
    storage.delete_encrypted(record.storage_name)
    db.delete(record)
    db.commit()

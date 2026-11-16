import os
import io

import pytest
from cryptography.exceptions import InvalidTag

from core import accounts, crypto, files, storage
from core.db import DB_PATH, SessionLocal, User
from core.security import secure_wipe


def test_crypto_roundtrip_and_tampering():
    key = bytearray(crypto.generate_key())
    nonce, ciphertext = crypto.encrypt_bytes(key, b"private bytes", b"context")
    assert ciphertext != b"private bytes"
    assert crypto.decrypt_bytes(key, nonce, ciphertext, b"context") == b"private bytes"
    with pytest.raises(InvalidTag):
        crypto.decrypt_bytes(key, nonce, ciphertext, b"other context")
    with pytest.raises(InvalidTag):
        crypto.decrypt_bytes(key, nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), b"context")
    secure_wipe(key)
    assert key == bytes(32)


def test_authentication_and_owner_bound_files(caplog):
    with SessionLocal() as db:
        alice = accounts.register_user(db, "alice", "master-password-a")
        bob = accounts.register_user(db, "bob", "master-password-b")
        for username, password in [("alice", "wrong-password"), ("missing", "master-password-a"),
                                   ("alice' OR 1=1 --", "master-password-a")]:
            with pytest.raises(accounts.AuthenticationError):
                accounts.authenticate_and_unlock(db, username, password)
        _, key = accounts.authenticate_and_unlock(db, "alice", "master-password-a")
        _, bob_key = accounts.authenticate_and_unlock(db, "bob", "master-password-b")
        record = files.store_file(db, alice.id, key, "notes.txt", b"secret file content")
        assert b"secret file content" not in storage.load_encrypted(record.storage_name)
        assert files.read_file(db, alice.id, record.id, key) == b"secret file content"
        with pytest.raises(FileNotFoundError):
            files.read_file(db, bob.id, record.id, bob_key)
        with pytest.raises(FileNotFoundError):
            files.remove_file(db, bob.id, record.id)
        with open(DB_PATH, "rb") as database_file:
            on_disk = database_file.read()
        assert b"master-password-a" not in on_disk
        files.remove_file(db, alice.id, record.id)
        assert not os.path.exists(storage.storage_path(record.storage_name))
        secure_wipe(key)
        secure_wipe(bob_key)
    for secret in ("master-password-a", "secret file content"):
        assert secret not in caplog.text


@pytest.mark.parametrize("name", ["", ".", "..", "../file", "a/b", r"a\b", "test;touch pwn", "name\n"])
def test_bad_filenames(name):
    with pytest.raises(storage.InvalidFileNameError):
        storage.sanitize_display_name(name)


def test_secure_delete_and_symlink_refusal(tmp_path, monkeypatch):
    path = tmp_path / "secret"
    path.write_bytes(b"secret contents")
    remove = storage.os.remove
    observed = []

    def observe_removal(target, **kwargs):
        observed.append(path.read_bytes())
        remove(target, **kwargs)

    monkeypatch.setattr(storage.os, "remove", observe_removal)
    storage.secure_delete_path(str(path))
    assert observed == [bytes(len(b"secret contents"))]
    assert not path.exists()
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        storage.secure_delete_path(str(link))
    with pytest.raises(OSError):
        storage.write_private_file(str(link), b"bad", overwrite=True)
    assert target.read_bytes() == b"keep"


def test_private_write_does_not_overwrite_without_force(tmp_path):
    path = tmp_path / "output"
    storage.write_private_file(str(path), b"first")
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        storage.write_private_file(str(path), b"second")
    storage.write_private_file(str(path), b"second", overwrite=True)
    assert path.read_bytes() == b"second"
    with pytest.raises(storage.InvalidPathError):
        storage.check_output_file("bad\x1bpath")


def test_exact_file_size_limit():
    with SessionLocal() as db:
        user = User(username="size-test", password_hash="hash", kdf_salt=b"salt",
                    wrapped_master_key=b"key", wrapped_master_key_nonce=b"nonce")
        db.add(user)
        db.commit()

        class SizedStream:
            def __init__(self, size):
                self.remaining = size

            def read(self, size):
                length = min(size, self.remaining)
                self.remaining -= length
                return b"x" * length

        key = bytearray(crypto.generate_key())
        record = files.store_file_stream(db, user.id, key, "large", SizedStream(storage.MAX_FILE_SIZE))
        assert record.original_name == "large"
        assert os.path.getsize(storage.storage_path(record.storage_name)) == storage.MAX_FILE_SIZE + 16
        existing = set(os.listdir(storage.STORAGE_DIR))
        with pytest.raises(storage.FileTooLargeError):
            files.store_file_stream(db, user.id, key, "too-large", SizedStream(storage.MAX_FILE_SIZE + 1))
        assert set(os.listdir(storage.STORAGE_DIR)) == existing
        files.remove_file(db, user.id, record.id)
        secure_wipe(key)


def test_streaming_file_compatibility_and_limit(monkeypatch):
    monkeypatch.setattr(storage, "MAX_FILE_SIZE", 2 * 1024 * 1024)
    with SessionLocal() as db:
        user = User(username="stream", password_hash="hash", kdf_salt=b"salt",
                    wrapped_master_key=b"key", wrapped_master_key_nonce=b"nonce")
        db.add(user)
        db.commit()
        key = bytearray(crypto.generate_key())
        content = b"x" * storage.MAX_FILE_SIZE

        class CheckedStream(io.BytesIO):
            def read(self, size=-1):
                assert 0 < size <= 1024 * 1024
                return super().read(size)

        record = files.store_file_stream(db, user.id, key, "stream", CheckedStream(content))
        assert files.read_file(db, user.id, record.id, key) == content
        existing = set(os.listdir(storage.STORAGE_DIR))
        with pytest.raises(storage.FileTooLargeError):
            files.store_file_stream(db, user.id, key, "too-large", CheckedStream(content + b"x"))
        assert set(os.listdir(storage.STORAGE_DIR)) == existing
        files.remove_file(db, user.id, record.id)
        secure_wipe(key)

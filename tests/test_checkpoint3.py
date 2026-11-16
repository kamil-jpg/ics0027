"""Reproducible attack demonstrations for the two file-manager checkpoints."""
import datetime
import io
import json
import os
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from core import accounts, crypto, files, storage
from core.db import FileRecord, SessionLocal, User, WebSession, engine
from core.security import audit, audit_source, secure_wipe
from src.cli import main as cli
from src.web import main, sessions


def csrf(client, path="/"):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text).group(1)


def sign_in(client, username="alice"):
    return client.post("/auth/login", data={
        "csrf_token": csrf(client, "/auth/login"), "username": username,
        "password": "checkpoint-master-secret",
    }, follow_redirects=False)


@pytest.fixture
def owner():
    with SessionLocal() as db:
        user = accounts.register_user(db, "alice", "checkpoint-master-secret")
        user_id = user.id
    with TestClient(main.app, base_url="https://testserver", client=("192.0.2.10", 1234)) as client:
        assert sign_in(client).status_code == 303
        yield client, user_id


def upload(client, name="notes.txt", content=b"file-plaintext-secret"):
    return client.post("/files/upload", data={"csrf_token": csrf(client)},
                       files={"file": (name, content)}, follow_redirects=False)


def test_file_csrf_demonstration_and_cross_session_token(owner):
    client, _ = owner
    assert upload(client).status_code == 303
    token = csrf(client)
    with SessionLocal() as db:
        file_id = db.query(FileRecord).one().id
    other = TestClient(main.app, base_url="https://testserver")
    try:
        assert sign_in(other).status_code == 303
        other_token = csrf(other)
        for attack in (None, "forged-token", other_token):
            data = {} if attack is None else {"csrf_token": attack}
            assert client.post("/files/upload", data=data,
                               files={"file": ("attack.txt", b"attack")}).status_code == 403
            assert client.post(f"/files/delete/{file_id}", data=data).status_code == 403
            assert client.post("/auth/logout", data=data).status_code == 403
        assert client.get(f"/files/download/{file_id}").content == b"file-plaintext-secret"
        with SessionLocal() as db:
            assert db.query(FileRecord).count() == 1
        assert client.post(f"/files/delete/{file_id}", data={"csrf_token": token},
                           follow_redirects=False).status_code == 303
    finally:
        other.close()


@pytest.mark.parametrize("name", ["attack.html", "attack.svg", "attack.php", "attack.py", "attack.exe", "no-extension"])
def test_disallowed_upload_types(owner, name):
    client, _ = owner
    assert upload(client, name).status_code == 400
    with SessionLocal() as db:
        assert db.query(FileRecord).count() == 0


def test_file_xss_payload_and_download_headers(owner):
    client, _ = owner
    attack = b'<script>alert("checkpoint-xss")</script>'
    assert upload(client, "<img src=x onerror=alert(1)>.txt", attack).status_code == 303
    page = client.get("/")
    assert "<img src=x" not in page.text
    with SessionLocal() as db:
        row = db.query(FileRecord).one()
        file_id = row.id
        # Also verify autoescaping for metadata from a legacy database.
        row.original_name = '<script>alert("checkpoint-xss")</script>.txt'
        db.commit()
    assert "&lt;script&gt;" in client.get("/").text
    with SessionLocal() as db:
        db.get(FileRecord, file_id).original_name = "safe.txt"
        db.commit()
    response = client.get(f"/files/download/{file_id}")
    assert response.content == attack
    assert response.headers["content-disposition"] == 'attachment; filename="safe.txt"'
    assert response.headers["content-type"] == "application/octet-stream"
    for response in (page, response):
        assert "script-src 'none'" in response.headers["content-security-policy"]
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("payload", ["' OR 1=1 --", "' UNION SELECT 1 --", "'; DROP TABLE files; --"])
def test_sql_injection_is_bound_and_cannot_select_owner_files(owner, payload):
    client, user_id = owner
    assert upload(client).status_code == 303
    calls = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        calls.append((statement, parameters))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        with SessionLocal() as db:
            assert sessions.get_session(db, payload) is None
            assert files.owned_file(db, user_id, payload) is None
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    bound = [(statement, parameters) for statement, parameters in calls if payload in parameters]
    assert len(bound) == 2
    assert all(payload not in statement and "?" in statement for statement, _ in bound)
    response = client.get("/files/download/1%20OR%201=1")
    assert response.status_code == 400
    with SessionLocal() as db:
        assert db.query(FileRecord).count() == 1
        assert db.query(User).count() == 1


def test_owner_scoped_cli_list_decrypt_delete_and_web_list(owner, tmp_path, monkeypatch, capsys):
    client, _ = owner
    assert upload(client).status_code == 303
    with SessionLocal() as db:
        accounts.register_user(db, "bob", "checkpoint-master-secret")
        row = db.query(FileRecord).one()
        file_id, blob = row.id, storage.storage_path(row.storage_name)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "checkpoint-master-secret")
    cli.main(["list", "-u", "bob"])
    assert "notes.txt" not in capsys.readouterr().out
    output = tmp_path / "denied.txt"
    for command in (
        ["decrypt", "-u", "bob", "-i", "notes.txt", "-o", str(output)],
        ["delete", "-u", "bob", "-i", "notes.txt", "-y"],
    ):
        with pytest.raises(SystemExit) as exc:
            cli.main(command)
        assert exc.value.code == 1
        assert "File not found" in capsys.readouterr().err
    assert not output.exists() and os.path.exists(blob)
    bob = TestClient(main.app, base_url="https://testserver")
    try:
        assert sign_in(bob, "bob").status_code == 303
        assert "notes.txt" not in bob.get("/").text
        assert bob.get(f"/files/download/{file_id}").status_code == 404
        assert bob.post(f"/files/delete/{file_id}", data={"csrf_token": csrf(bob)}).status_code == 404
    finally:
        bob.close()
    cli.main(["delete", "-u", "alice", "-i", "notes.txt", "-y"])
    assert not os.path.exists(blob)
    assert client.get(f"/files/download/{file_id}").status_code == 404


def test_stored_file_is_overwritten_before_web_deletion(owner, monkeypatch):
    client, _ = owner
    assert upload(client).status_code == 303
    with SessionLocal() as db:
        row = db.query(FileRecord).one()
        file_id, path = row.id, storage.storage_path(row.storage_name)
    original = storage.os.remove
    observed = []

    def capture(name, **kwargs):
        with open(path, "rb") as file:
            observed.append(file.read())
        return original(name, **kwargs)

    monkeypatch.setattr(storage.os, "remove", capture)
    assert client.post(f"/files/delete/{file_id}", data={"csrf_token": csrf(client)},
                       follow_redirects=False).status_code == 303
    assert observed == [bytes(len(b"file-plaintext-secret") + 16)]
    assert not os.path.exists(path)
    with SessionLocal() as db:
        assert db.query(FileRecord).count() == 0


@pytest.mark.parametrize("operation", ["read", "write", "wipe"])
def test_symlink_parent_and_traversal_refused(tmp_path, operation):
    directory = tmp_path / "real"
    directory.mkdir()
    path = directory / "file.txt"
    path.write_bytes(b"must survive")
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    for candidate in (link / "file.txt", directory / ".." / "real" / "file.txt"):
        with pytest.raises((OSError, storage.InvalidPathError)):
            if operation == "read":
                with storage.open_input_file(str(candidate)):
                    pass
            elif operation == "write":
                storage.write_private_file(str(candidate), b"replacement", overwrite=True)
            else:
                storage.secure_delete_path(str(candidate))
    assert path.read_bytes() == b"must survive"


def test_hard_link_write_and_wipe_refused(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_bytes(b"must survive")
    link = tmp_path / "hardlink"
    link.hardlink_to(path)
    with pytest.raises(storage.InvalidPathError):
        storage.write_private_file(str(link), b"replacement", overwrite=True)
    with pytest.raises(storage.InvalidPathError):
        storage.secure_delete_path(str(link))
    assert path.read_bytes() == b"must survive"


def test_ciphertext_symlinks_and_tampering_fail_closed(owner, tmp_path):
    client, _ = owner
    assert upload(client).status_code == 303
    with SessionLocal() as db:
        row = db.query(FileRecord).one()
        file_id, path = row.id, storage.storage_path(row.storage_name)
    with open(path, "r+b") as blob:
        value = blob.read(1)
        blob.seek(0)
        blob.write(bytes([value[0] ^ 1]))
    response = client.get(f"/files/download/{file_id}")
    assert response.status_code == 500 and "plaintext-secret" not in response.text
    os.unlink(path)
    target = tmp_path / "outside.txt"
    target.write_bytes(b"do not read or wipe")
    os.symlink(target, path)
    assert client.get(f"/files/download/{file_id}").status_code == 500
    assert client.post(f"/files/delete/{file_id}", data={"csrf_token": csrf(client)}).status_code == 500
    assert target.read_bytes() == b"do not read or wipe"


@pytest.mark.parametrize("fail", [False, True])
def test_encryption_buffers_are_wiped_on_success_and_failure(owner, monkeypatch, fail):
    _, user_id = owner
    buffers = []

    class Source(io.BytesIO):
        def readinto(self, buffer):
            buffers.append(buffer)
            count = super().readinto(buffer)
            if fail:
                raise OSError("sample read failure")
            return count

    key = bytearray(crypto.generate_key())
    try:
        with SessionLocal() as db:
            existing = set(os.listdir(storage.STORAGE_DIR))
            if fail:
                with pytest.raises(OSError):
                    files.store_file_stream(db, user_id, key, "data.txt", Source(b"private bytes"))
                assert set(os.listdir(storage.STORAGE_DIR)) == existing
            else:
                row = files.store_file_stream(db, user_id, key, "data.txt", Source(b"private bytes"))
                assert files.read_file(db, user_id, row.id, key) == b"private bytes"
    finally:
        secure_wipe(key)
    assert buffers and all(buffer == bytes(len(buffer)) for buffer in buffers)


def test_download_plaintext_wiped_and_log_fields_secret_free(owner, caplog, monkeypatch):
    client, user_id = owner
    assert upload(client).status_code == 303
    with SessionLocal() as db:
        file_id = db.query(FileRecord).one().id
    wiped = []
    original = main.secure_wipe

    def capture(buffer):
        if buffer == b"file-plaintext-secret":
            wiped.append(buffer)
        original(buffer)

    monkeypatch.setattr(main, "secure_wipe", capture)
    assert client.get(f"/files/download/{file_id}").content == b"file-plaintext-secret"
    assert wiped and all(buffer == bytes(len(buffer)) for buffer in wiped)
    token = csrf(client)
    session_id = client.cookies.get(main.COOKIE_NAME)
    key = sessions._master_key_cache[session_id]
    key_hex = key.hex()
    assert client.post("/auth/logout", data={"csrf_token": token}, follow_redirects=False).status_code == 303
    assert key == bytes(len(key)) and session_id not in sessions._master_key_cache
    records = [json.loads(record.message) for record in caplog.records if record.name == "secfile.security"]
    assert {"file_encrypt", "file_decrypt", "session_destroy"} <= {r["event"] for r in records}
    for record in records:
        assert datetime.datetime.fromisoformat(record["timestamp"]).utcoffset() == datetime.timedelta(0)
        assert record["source_address"] == "192.0.2.10"
        assert record["user_id"] == user_id
    for secret in ("checkpoint-master-secret", "file-plaintext-secret", token, session_id, key_hex):
        assert secret not in caplog.text


def test_session_rotation_and_absolute_expiry(owner):
    client, _ = owner
    old_token = client.cookies.get(main.COOKIE_NAME)
    old_key = sessions._master_key_cache[old_token]
    response = sign_in(client)
    assert response.status_code == 303
    assert all(flag in response.headers["set-cookie"] for flag in ("Secure", "HttpOnly", "SameSite=strict"))
    token = client.cookies.get(main.COOKIE_NAME)
    assert token != old_token and old_key == bytes(len(old_key))
    key = sessions._master_key_cache[token]
    with SessionLocal() as db:
        assert db.query(WebSession).filter_by(session_token=old_token).first() is None
        db.query(WebSession).filter_by(session_token=token).one().expires_at = sessions._now() - datetime.timedelta(seconds=1)
        db.commit()
    assert client.get("/", follow_redirects=False).status_code == 303
    assert key == bytes(len(key))


def test_failed_logout_still_wipes_key(owner, monkeypatch):
    client, _ = owner
    token = client.cookies.get(main.COOKIE_NAME)
    key = sessions._master_key_cache[token]
    with SessionLocal() as db:
        monkeypatch.setattr(db, "commit", lambda: (_ for _ in ()).throw(RuntimeError("database failure")))
        with pytest.raises(RuntimeError):
            sessions.destroy_session(db, token)
    assert key == bytes(len(key)) and token not in sessions._master_key_cache
    assert client.get("/", follow_redirects=False).status_code == 303


def test_file_internal_errors_and_cli_cleanup_are_secret_free(owner, tmp_path, monkeypatch, caplog, capsys):
    client, _ = owner
    assert upload(client).status_code == 303
    with SessionLocal() as db:
        file_id = db.query(FileRecord).one().id
    keys = []
    plaintexts = []
    original_unlock = cli._unlock

    def unlock(db, username):
        user, key = original_unlock(db, username)
        keys.append(key)
        return user, key

    def fail_write(path, data, **kwargs):
        plaintexts.append(data)
        raise OSError("private-internal-path-and-secret")

    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "checkpoint-master-secret")
    monkeypatch.setattr(cli, "_unlock", unlock)
    monkeypatch.setattr(storage, "write_private_file", fail_write)
    with pytest.raises(SystemExit) as exc:
        cli.main(["decrypt", "-u", "alice", "-i", "notes.txt", "-o", str(tmp_path / "output")])
    assert exc.value.code == 1
    assert capsys.readouterr().err == "Error: The request could not be completed.\n"
    assert keys and plaintexts and all(buffer == bytes(len(buffer)) for buffer in keys + plaintexts)

    def fail_read(*args):
        raise RuntimeError("private-internal-path-and-secret")

    monkeypatch.setattr(files, "read_file", fail_read)
    response = client.get(f"/files/download/{file_id}")
    assert response.status_code == 500
    assert response.text == "The request could not be completed."
    assert "private-internal-path-and-secret" not in caplog.text


def test_anonymous_file_operations_and_preauth_token_expiry():
    with TestClient(main.app, base_url="https://testserver") as client:
        for path in ("/", "/files/upload", "/files/download/1"):
            assert client.get(path, follow_redirects=False).headers["location"] == "/auth/login"
        assert client.post("/files/delete/1", data={"csrf_token": "fake"}, follow_redirects=False).status_code == 303
        assert client.post("/files/upload", data={"csrf_token": "fake"},
                           files={"file": ("attack.txt", b"attack")}, follow_redirects=False).status_code == 303
        token = csrf(client, "/auth/register")
        cookie = client.cookies.get("preauth")
        main._preauth[cookie] = (token, 0)
        response = client.post("/auth/register", data={
            "csrf_token": token, "username": "attack", "password": "sample-password",
            "confirm_password": "sample-password",
        })
        assert response.status_code == 403
        with SessionLocal() as db:
            assert db.query(User).count() == 0 and db.query(FileRecord).count() == 0


@pytest.mark.parametrize("content", [b"", bytes(range(256)) * 17])
def test_empty_and_binary_files_and_wrong_key(owner, content):
    from cryptography.exceptions import InvalidTag

    client, user_id = owner
    assert upload(client, "sample.bin", content).status_code == 303
    with SessionLocal() as db:
        file_id = db.query(FileRecord).one().id
        with pytest.raises(InvalidTag):
            files.read_file(db, user_id, file_id, crypto.generate_key())
    assert client.get(f"/files/download/{file_id}").content == content


def test_audit_rejects_arbitrary_fields_and_untrusted_address(caplog):
    with pytest.raises(ValueError):
        audit("password-secret", "failure")
    with pytest.raises(ValueError):
        audit("file", "password-secret")
    with pytest.raises(ValueError):
        audit("file", "success", "password-secret")
    with audit_source("password-secret\nforged event"):
        audit("file", "failure")
    audit("local_wipe", "success")
    records = [json.loads(record.message) for record in caplog.records]
    assert [r["source_address"] for r in records] == ["unknown", "local"]
    assert "password-secret" not in caplog.text


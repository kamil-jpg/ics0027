import datetime
import json
import re

from fastapi.testclient import TestClient

from core.db import SessionLocal, WebSession
from src.web import main, sessions


def token(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def register(client, name, password):
    csrf = token(client.get("/auth/register").text)
    return client.post("/auth/register", data={
        "csrf_token": csrf, "username": name, "password": password, "confirm_password": password,
    }, follow_redirects=False)


def login(client, name, password):
    csrf = token(client.get("/auth/login").text)
    return client.post("/auth/login", data={
        "csrf_token": csrf, "username": name, "password": password,
    }, follow_redirects=False)


def test_web_attacks_and_owner_isolation(caplog):
    with TestClient(main.app, base_url="https://testserver") as alice:
        assert alice.post("/auth/register", data={
            "username": "attack", "password": "password", "confirm_password": "password",
        }).status_code == 403
        assert alice.post("/auth/login", data={"username": "alice", "password": "password"}).status_code == 403
        assert register(alice, "alice", "alice-master-password").status_code == 303
        assert register(alice, "bob", "bob-master-password").status_code == 303
        assert login(alice, "alice' OR 1=1 --", "alice-master-password").status_code == 401
        assert login(alice, "alice", "wrong-password").status_code == 401
        assert login(alice, "alice", "alice-master-password").status_code == 303
        cookie = alice.cookies.get("session_id")
        assert cookie and "Secure" in alice.get("/auth/login").headers.get("set-cookie", "")
        csrf = token(alice.get("/").text)
        assert alice.post("/files/upload", data={"csrf_token": "bad"},
                          files={"file": ("safe.txt", b"file-secret")}).status_code == 403
        assert alice.post("/files/upload", data={"csrf_token": csrf},
                          files={"file": ("../../safe.txt", b"file-secret")},
                          follow_redirects=False).status_code == 303
        html = alice.get("/").text
        file_id = int(re.search(r"/files/download/(\d+)", html).group(1))
        assert alice.get(f"/files/download/{file_id}").content == b"file-secret"
        assert alice.post(f"/files/delete/{file_id}", data={"csrf_token": "bad"}).status_code == 403
        assert alice.post("/auth/logout", data={"csrf_token": "bad"}).status_code == 403
        assert alice.post(f"/files/delete/{file_id}", data={"csrf_token": "😈"}).status_code == 403

        bob = TestClient(main.app, base_url="https://testserver")
        try:
            assert login(bob, "bob", "bob-master-password").status_code == 303
            bob_csrf = token(bob.get("/").text)
            assert bob.get(f"/files/download/{file_id}").status_code == 404
            assert bob.post(f"/files/delete/{file_id}", data={"csrf_token": bob_csrf}).status_code == 404
            assert alice.get(f"/files/download/{file_id}").content == b"file-secret"
            assert alice.post(f"/files/delete/{file_id}", data={"csrf_token": csrf},
                              follow_redirects=False).status_code == 303
            assert alice.get(f"/files/download/{file_id}").status_code == 404
            assert alice.post("/auth/logout", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
            assert alice.get("/", follow_redirects=False).status_code == 303
        finally:
            bob.close()

    for secret in ("alice-master-password", "bob-master-password", "file-secret"):
        assert secret not in caplog.text
    events = [json.loads(record.message) for record in caplog.records if record.name == "secfile.security"]
    assert events and all(set(event) == {
        "event", "outcome", "user_id", "timestamp", "source_address"
    } for event in events)


def test_session_expiry_wipes_key():
    with TestClient(main.app, base_url="https://testserver") as client:
        register(client, "alice", "alice-master-password")
        login(client, "alice", "alice-master-password")
        session_id = client.cookies.get("session_id")
        key = sessions._master_key_cache[session_id]
        with SessionLocal() as db:
            row = db.query(WebSession).filter_by(session_token=session_id).one()
            row.last_seen_at = sessions._now() - datetime.timedelta(minutes=16)
            db.commit()
        assert client.get("/", follow_redirects=False).status_code == 303
        assert key == bytes(len(key))
        assert session_id not in sessions._master_key_cache


def test_request_limits_and_generic_validation():
    with TestClient(main.app, base_url="https://testserver") as client:
        response = client.post("/auth/login", content=b"x" * (main.MAX_FORM_SIZE + 1))
        assert response.status_code == 413
        response = client.post("/auth/login", data={"username": "x", "password": "do-not-echo" * 20})
        assert response.status_code == 400
        assert "do-not-echo" not in response.text
        response = client.post("/auth/login",
                               content=iter([b"username=", b"x" * (main.MAX_FORM_SIZE + 1)]),
                               headers={"content-type": "application/x-www-form-urlencoded"})
        assert response.status_code == 413
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404


def test_oversized_upload_and_csrf_replay(monkeypatch):
    monkeypatch.setattr(main.storage, "MAX_FILE_SIZE", 16)
    with TestClient(main.app, base_url="https://testserver") as client:
        csrf = token(client.get("/auth/register").text)
        payload = {"csrf_token": csrf, "username": "alice", "password": "alice-master-password",
                   "confirm_password": "alice-master-password"}
        assert client.post("/auth/register", data=payload, follow_redirects=False).status_code == 303
        assert client.post("/auth/register", data=payload).status_code == 403
        assert login(client, "alice", "alice-master-password").status_code == 303
        csrf = token(client.get("/").text)
        result = client.post("/files/upload", data={"csrf_token": csrf}, files={"file": ("file.txt", b"x" * 17)})
        assert result.status_code == 413
        assert "file.txt" not in client.get("/").text


def test_authentication_rate_limit():
    with TestClient(main.app, base_url="https://testserver") as client:
        for _ in range(10):
            assert login(client, "missing", "wrong-password").status_code == 401
        assert login(client, "missing", "wrong-password").status_code == 429


def test_internal_errors_are_generic_and_secret_free(monkeypatch, caplog):
    with TestClient(main.app, base_url="https://testserver") as client:
        register(client, "alice", "alice-master-password")
        login(client, "alice", "alice-master-password")

        csrf = token(client.get("/").text)
        client.post("/files/upload", data={"csrf_token": csrf}, files={"file": ("file.txt", b"x")})

        def fail(*args):
            raise RuntimeError("internal detail and secret-value")

        monkeypatch.setattr(main.files, "read_file", fail)
        response = client.get("/files/download/1")
        assert response.status_code == 500
        assert "secret-value" not in response.text
        assert "secret-value" not in caplog.text


def test_request_key_copies_are_wiped(monkeypatch):
    with TestClient(main.app, base_url="https://testserver") as client:
        register(client, "alice", "alice-master-password")
        login(client, "alice", "alice-master-password")
        original = sessions.get_master_key
        copies = []

        def capture(session_token):
            key = original(session_token)
            copies.append(key)
            return key

        monkeypatch.setattr(sessions, "get_master_key", capture)
        csrf = token(client.get("/").text)
        assert client.post("/files/upload", data={"csrf_token": csrf},
                           files={"file": ("file.txt", b"secret")}, follow_redirects=False).status_code == 303
        assert client.get("/files/download/1").content == b"secret"
        assert copies and all(key == bytes(len(key)) for key in copies)


def test_large_multipart_upload_stays_in_memory(monkeypatch):
    with TestClient(main.app, base_url="https://testserver") as client:
        register(client, "alice", "alice-master-password")
        login(client, "alice", "alice-master-password")
        csrf = token(client.get("/").text)
        original = main.files.store_file_stream
        checked = []

        def capture(db, user_id, key, name, source):
            checked.append(not source._rolled)
            return original(db, user_id, key, name, source)

        monkeypatch.setattr(main.files, "store_file_stream", capture)
        response = client.post("/files/upload", data={"csrf_token": csrf},
                               files={"file": ("large.txt", b"x" * (2 * 1024 * 1024))},
                               follow_redirects=False)
        assert response.status_code == 303
        assert checked == [True]

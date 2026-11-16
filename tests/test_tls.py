"""Local HTTPS smoke test with a temporary certificate and isolated application data."""
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is needed for the local TLS smoke test")
def test_real_https_server(tmp_path):
    certificate = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate), "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    environment = {**os.environ, "SECFILE_DATA_DIR": str(tmp_path / "data"),
                   "SECFILE_STORAGE_DIR": str(tmp_path / "encrypted")}
    server = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "src.web.main:app", "--host", "127.0.0.1",
        "--port", str(port), "--ssl-keyfile", str(key), "--ssl-certfile", str(certificate),
        "--no-access-log", "--no-proxy-headers",
    ], cwd=Path(__file__).resolve().parents[1], env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        context = ssl.create_default_context(cafile=str(certificate))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic() + 15
        while True:
            try:
                response = opener.open(f"https://localhost:{port}/auth/login", timeout=1)
                break
            except (urllib.error.URLError, TimeoutError):
                assert server.poll() is None, "HTTPS server exited before becoming ready"
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        with response:
            assert response.status == 200
            assert b'name="csrf_token"' in response.read()
            assert "Secure" in response.headers["set-cookie"]
            assert "HttpOnly" in response.headers["set-cookie"]
            assert response.headers["strict-transport-security"] == "max-age=31536000"
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

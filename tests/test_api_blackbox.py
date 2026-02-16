import signal
import subprocess
import time

import jwt
import requests
import pytest

BASE = "http://127.0.0.1:8080"


def wait_for_server(timeout=8) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BASE}/health", timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


@pytest.fixture(scope="session", autouse=True)
def jwks_server():
    """
    Start the server once for the whole test session.
    """
    proc = subprocess.Popen(
        ["uvicorn", "src.jwks_server.main:app", "--host", "127.0.0.1", "--port", "8080"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert wait_for_server(), "Server did not start on time"
        yield
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def test_health():
    r = requests.get(f"{BASE}/health", timeout=3)
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_blackbox_auth_and_jwks():
    # POST /auth with no body
    r = requests.post(f"{BASE}/auth", timeout=3)
    assert r.status_code == 200
    token = r.json()["token"]

    # JWT should have kid header
    header = jwt.get_unverified_header(token)
    assert "kid" in header

    # JWKS should include that kid (token signed by active key)
    jwks = requests.get(f"{BASE}/jwks", timeout=3).json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert header["kid"] in kids


def test_auth_expired_and_not_in_jwks():
    # Request expired token
    r = requests.post(f"{BASE}/auth?expired=true", timeout=3)
    assert r.status_code == 200
    expired_token = r.json()["token"]

    # Exp claim should be expired
    payload = jwt.decode(expired_token, options={"verify_signature": False})
    assert payload["exp"] <= int(time.time())

    # Expired key's kid should NOT be served by /jwks (unexpired only)
    expired_header = jwt.get_unverified_header(expired_token)
    jwks = requests.get(f"{BASE}/jwks", timeout=3).json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert expired_header["kid"] not in kids


def test_jwks_with_unknown_kid_returns_empty():
    r = requests.get(f"{BASE}/jwks?kid=this_kid_does_not_exist", timeout=3)
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert data["keys"] == []



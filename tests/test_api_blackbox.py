import os
import signal
import subprocess
import time

import requests
import jwt


BASE = "http://localhost:8080"


def wait_for_server(timeout=8):
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


def test_blackbox_auth_and_jwks():
    # Start server
    proc = subprocess.Popen(
        ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8080"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert wait_for_server(), "Server did not start on time"

        # POST /auth with no body
        r = requests.post(f"{BASE}/auth", timeout=3)
        assert r.status_code == 200
        token = r.json()["token"]

        # JWT should have kid header
        header = jwt.get_unverified_header(token)
        assert "kid" in header

        # GET /jwks should include that kid (since token is signed by active key)
        jwks = requests.get(f"{BASE}/jwks", timeout=3).json()
        kids = {k["kid"] for k in jwks["keys"]}
        assert header["kid"] in kids

        # expired token flow
        r2 = requests.post(f"{BASE}/auth?expired=true", timeout=3)
        assert r2.status_code == 200
        expired_token = r2.json()["token"]
        exp_claim = jwt.decode(expired_token, options={"verify_signature": False})["exp"]
        assert exp_claim <= int(time.time())

    finally:
        # stop server
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

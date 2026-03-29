import os
import sqlite3
import threading
import time
from http.server import HTTPServer

import jwt
import pytest
import requests

from main import DB_FILE, HOST_NAME, MyServer, SERVER_PORT, initialize_database

BASE_URL = f"http://{HOST_NAME}:{SERVER_PORT}"


@pytest.fixture(scope="module")
def server():
    # Fresh DB every test run — leftover state from a previous run can cause
    # confusing failures, so we wipe it before doing anything else.
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    initialize_database()

    # Spin the server up in a daemon thread so it dies automatically when
    # the test process exits, no manual cleanup required.
    server_address = (HOST_NAME, SERVER_PORT)
    httpd = HTTPServer(server_address, MyServer)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    # Poll until the server is actually accepting connections before handing
    # control to the tests. 20 attempts × 100ms = 2 second budget, which is
    # more than enough on any reasonable machine.
    for _ in range(20):
        try:
            requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=1)
            break
        except requests.ConnectionError:
            time.sleep(0.1)

    yield httpd

    # Teardown: stop the server cleanly after all module-scoped tests finish.
    httpd.shutdown()
    httpd.server_close()


def test_database_file_exists(server):
    # Basic sanity check — if the DB file isn't there, nothing else will work.
    assert os.path.exists(DB_FILE)


def test_database_contains_valid_and_expired_keys(server):
    # The server is supposed to seed the DB with at least one valid key and
    # one already-expired key. This test verifies that contract holds.
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM keys")
    total = cursor.fetchone()[0]

    now = int(time.time())

    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,))
    valid_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
    expired_count = cursor.fetchone()[0]

    conn.close()

    assert total >= 2
    assert valid_count >= 1
    assert expired_count >= 1


def test_jwks_returns_valid_keys(server):
    # Hits the standard JWKS discovery endpoint and checks that the response
    # is well-formed: correct status, correct content type, and at least one
    # key with all the fields a JWT verifier would need.
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=5)

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    body = response.json()
    assert "keys" in body
    assert len(body["keys"]) >= 1

    key = body["keys"][0]
    assert key["alg"] == "RS256"
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert "kid" in key  # key ID — used to look up the right public key when verifying
    assert "n" in key    # RSA modulus
    assert "e" in key    # RSA public exponent


def test_auth_returns_valid_jwt(server):
    # A normal POST /auth should give back a three-part JWT (header.payload.sig)
    # signed with a non-expired key. We skip signature verification here since
    # that's covered by the JWKS test; we just care about the shape and expiry.
    response = requests.post(f"{BASE_URL}/auth", timeout=5)

    assert response.status_code == 200

    token = response.text
    assert len(token.split(".")) == 3  # must be a proper JWT, not some error string

    payload = jwt.decode(
        token,
        options={"verify_signature": False, "verify_exp": False},
        algorithms=["RS256"],
    )
    assert payload["exp"] > int(time.time())  # token should not already be expired


def test_auth_accepts_basic_auth_and_json(server):
    # The server doesn't actually validate credentials — it issues a token for
    # the hardcoded test user regardless. This just confirms that sending extra
    # headers/body (like a real client might) doesn't break anything.
    response = requests.post(
        f"{BASE_URL}/auth",
        auth=("userABC", "password123"),
        json={"username": "userABC", "password": "password123"},
        timeout=5,
    )

    assert response.status_code == 200
    assert len(response.text.split(".")) == 3


def test_auth_expired_returns_expired_jwt(server):
    # POST /auth?expired is the escape hatch for testing token rejection.
    # The returned token should be signed with an already-expired key,
    # meaning its exp claim will be in the past.
    response = requests.post(f"{BASE_URL}/auth?expired=true", timeout=5)

    assert response.status_code == 200

    token = response.text
    payload = jwt.decode(
        token,
        options={"verify_signature": False, "verify_exp": False},
        algorithms=["RS256"],
    )
    assert payload["exp"] <= int(time.time())  # must be expired, not just "soon to expire"


# --- Method-not-allowed tests ---
# These are mostly mechanical: each endpoint only accepts one HTTP method,
# and everything else should come back with a 405.

def test_auth_method_not_allowed(server):
    # /auth is POST-only; GET should be rejected.
    response = requests.get(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_jwks_method_not_allowed(server):
    # /.well-known/jwks.json is GET-only; POST should be rejected.
    response = requests.post(f"{BASE_URL}/.well-known/jwks.json", timeout=5)
    assert response.status_code == 405


def test_invalid_endpoint(server):
    # Any path the server doesn't recognize should return 405, not 404.
    # This is how the server is wired — unrecognized routes fall through to send_405().
    response = requests.get(f"{BASE_URL}/invalid", timeout=5)
    assert response.status_code == 405


def test_put_method_not_allowed(server):
    response = requests.put(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_patch_method_not_allowed(server):
    response = requests.patch(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_delete_method_not_allowed(server):
    response = requests.delete(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_head_method_not_allowed(server):
    response = requests.head(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405
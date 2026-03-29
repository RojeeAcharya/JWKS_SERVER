import base64
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Where the server listens and what DB file it uses.
# The DB name is intentionally goofy — this is a toy auth server for testing.
HOST_NAME = "127.0.0.1"
SERVER_PORT = 8080
JWT_ALGORITHM = "RS256"
DB_FILE = "totally_not_my_privateKeys.db"


def unix_now() -> int:
    # Just a quick helper to get the current time as a Unix timestamp.
    # Used everywhere for expiry comparisons.
    return int(time.time())


def encode_base64url_uint(value: int) -> str:
    # Converts a big integer (like an RSA modulus or exponent) into the
    # base64url format that the JWKS spec requires. The padding strip at
    # the end is required — JWK doesn't use base64 padding characters.
    byte_count = (value.bit_length() + 7) // 8
    raw_bytes = value.to_bytes(byte_count, "big")
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("utf-8")


def generate_private_key_pem() -> bytes:
    # Generates a fresh 2048-bit RSA key and returns it as a PEM byte string.
    # We don't encrypt the PEM since it lives in a local SQLite DB anyway.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem_data: bytes):
    # Deserializes a PEM byte string back into a key object we can actually use.
    return serialization.load_pem_private_key(pem_data, password=None)


def build_jwk(kid: int, pem_data: bytes) -> dict:
    # Takes a key ID and its PEM data and returns the public half as a JWK dict.
    # The private key never leaves this function — we only expose n and e.
    private_key = load_private_key(pem_data)
    public_numbers = private_key.public_key().public_numbers()

    return {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "n": encode_base64url_uint(public_numbers.n),
        "e": encode_base64url_uint(public_numbers.e),
    }


def db_connection():
    # Opens (or creates) the SQLite database. Called fresh each time rather
    # than keeping a long-lived connection, which keeps things simple.
    return sqlite3.connect(DB_FILE)


def initialize_database() -> None:
    # Sets up the keys table on first run, then makes sure we have at least
    # one valid key and one intentionally expired key in the database.
    # The expired key exists so we can test token rejection flows.
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

        now = unix_now()

        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,))
        valid_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
        expired_count = cursor.fetchone()[0]

        # Only insert a new valid key if there isn't one already.
        if valid_count == 0:
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key_pem(), now + 3600),  # expires in 1 hour
            )

        # Same deal for expired keys — we want one for testing bad tokens.
        if expired_count == 0:
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key_pem(), now - 3600),  # already expired 1 hour ago
            )

        conn.commit()


def fetch_valid_key():
    # Grabs the oldest non-expired key from the DB.
    # If we somehow have none (e.g. they all expired), it generates a new one
    # and tries again. The recursion terminates after one retry in practice.
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC LIMIT 1",
            (unix_now(),),
        )
        row = cursor.fetchone()

    if row is None:
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key_pem(), unix_now() + 3600),
            )
            conn.commit()
        return fetch_valid_key()

    return row


def fetch_expired_key():
    # Same pattern as fetch_valid_key, but for expired keys.
    # Used when a caller wants a token that should fail signature validation.
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid ASC LIMIT 1",
            (unix_now(),),
        )
        row = cursor.fetchone()

    if row is None:
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (generate_private_key_pem(), unix_now() - 3600),
            )
            conn.commit()
        return fetch_expired_key()

    return row


def fetch_all_valid_keys():
    # Returns every currently-valid key. Used to build the JWKS response,
    # which may list multiple keys if we're in the middle of a key rotation.
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC",
            (unix_now(),),
        )
        return cursor.fetchall()


def create_jwks_response() -> dict:
    # Builds the full JWKS payload for the /.well-known/jwks.json endpoint.
    # Only public key material goes here — never the private keys.
    keys = []
    for kid, pem_data, _exp in fetch_all_valid_keys():
        keys.append(build_jwk(kid, pem_data))
    return {"keys": keys}


def create_jwt(use_expired: bool) -> str:
    # Signs a JWT for the hardcoded test user "userABC".
    # Pass use_expired=True to get a token signed with an expired key —
    # useful for testing how your app handles invalid tokens.
    if use_expired:
        kid, pem_data, exp_value = fetch_expired_key()
    else:
        kid, pem_data, exp_value = fetch_valid_key()

    private_key = load_private_key(pem_data)

    payload = {
        "sub": "userABC",
        "username": "userABC",
        "iat": unix_now(),
        "exp": exp_value,  # inherited directly from the key's expiry
    }

    headers = {
        "alg": JWT_ALGORITHM,
        "kid": str(kid),  # tells verifiers which JWKS key to look up
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm=JWT_ALGORITHM,
        headers=headers,
    )

    # Older versions of PyJWT return bytes; newer ones return str. Handle both.
    if isinstance(token, bytes):
        return token.decode("utf-8")
    return token


class MyServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence the default request logging — too noisy during testing.
        return

    def send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status_code: int, payload: str) -> None:
        body = payload.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_405(self) -> None:
        self.send_text(405, "Method Not Allowed")

    def consume_request_body(self) -> None:
        # Drains the request body so the connection stays clean,
        # even for endpoints that don't use the body.
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > 0:
            self.rfile.read(content_length)

    def do_GET(self):
        parsed = urlparse(self.path)

        # The only GET endpoint: the standard JWKS discovery URL.
        # Clients use this to fetch public keys for token verification.
        if parsed.path == "/.well-known/jwks.json":
            self.send_json(200, create_jwks_response())
            return

        self.send_405()

    def do_POST(self):
        parsed = urlparse(self.path)

        # POST /auth issues a JWT for the test user.
        # Add ?expired to the query string to get a token that's already invalid.
        # Example: POST /auth?expired
        if parsed.path == "/auth":
            self.consume_request_body()
            params = parse_qs(parsed.query)
            use_expired = "expired" in params
            token = create_jwt(use_expired)
            self.send_text(200, token)
            return

        self.send_405()

    # Everything else gets a 405. This server only does GET and POST.
    def do_PUT(self):
        self.send_405()

    def do_PATCH(self):
        self.send_405()

    def do_DELETE(self):
        self.send_405()

    def do_HEAD(self):
        self.send_405()


def run():
    initialize_database()
    server = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    print(f"Server running on http://{HOST_NAME}:{SERVER_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
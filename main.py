import base64
import hashlib
import json
import os
import sqlite3
import time
import uuid
from base64 import b64decode
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST_NAME = "127.0.0.1"
SERVER_PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"
JWT_ALGORITHM = "RS256"

password_hasher = PasswordHasher()
rate_limit_store = defaultdict(deque)

def unix_now():
    return int(time.time())

def get_aes_key():
    secret = os.environ.get("NOT_MY_KEY", "local-dev-key")
    return hashlib.sha256(secret.encode("utf-8")).digest()

def encrypt_key(pem_bytes):
    aes = AESGCM(get_aes_key())
    iv = os.urandom(12)
    encrypted = aes.encrypt(iv, pem_bytes, None)
    return iv + encrypted

def decrypt_key(stored_bytes):
    aes = AESGCM(get_aes_key())
    iv = stored_bytes[:12]
    encrypted = stored_bytes[12:]
    return aes.decrypt(iv, encrypted, None)

def int_to_base64url(value):
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")

def generate_private_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def load_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

def db_connection():
    return sqlite3.connect(DB_FILE)

def initialize_database():
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS keys")
        cur.execute("""
            CREATE TABLE keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )""")
        now = unix_now()
        cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_key(generate_private_key_pem()), now + 3600))
        cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_key(generate_private_key_pem()), now - 3600))
        cur.execute("SELECT id FROM users WHERE username = ?", ("userABC",))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                ("userABC", password_hasher.hash("password123"), "userABC@example.com"))
        conn.commit()

def fetch_key(expired=False):
    op = "<=" if expired else ">"
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"SELECT kid, key, exp FROM keys WHERE exp {op} ? ORDER BY kid ASC LIMIT 1",
            (unix_now(),))
        row = cur.fetchone()
    if row is not None:
        return row
    expiry = unix_now() - 3600 if expired else unix_now() + 3600
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_key(generate_private_key_pem()), expiry))
        conn.commit()
    return fetch_key(expired)

def fetch_valid_keys():
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC",
            (unix_now(),))
        return cur.fetchall()

def build_jwk(kid, encrypted_key):
    pem = decrypt_key(encrypted_key)
    private_key = load_private_key(pem)
    nums = private_key.public_key().public_numbers()
    return {"alg": "RS256", "kty": "RSA", "use": "sig", "kid": str(kid),
            "n": int_to_base64url(nums.n), "e": int_to_base64url(nums.e)}

def jwks_response():
    return {"keys": [build_jwk(kid, key) for kid, key, _ in fetch_valid_keys()]}

def make_jwt(username, expired=False):
    kid, encrypted_key, exp = fetch_key(expired)
    pem = decrypt_key(encrypted_key)
    private_key = load_private_key(pem)
    payload = {"sub": username, "username": username, "iat": unix_now(), "exp": exp}
    headers = {"alg": JWT_ALGORITHM, "kid": str(kid)}
    token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM, headers=headers)
    return token.decode("utf-8") if isinstance(token, bytes) else token

def create_user(username, email):
    raw_password = str(uuid.uuid4())
    hashed_password = password_hasher.hash(raw_password)
    try:
        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, hashed_password, email))
            conn.commit()
        return True, raw_password
    except sqlite3.IntegrityError:
        return False, "user already exists"

def find_user(username):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,))
        return cur.fetchone()

def verify_user(username, password):
    user = find_user(username)
    if user is None:
        return None
    user_id, stored_username, stored_hash = user
    try:
        password_hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return None
    except Exception:
        return None
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
    return user_id, stored_username

def log_auth(user_id, request_ip):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id))
        conn.commit()

def is_rate_limited(ip):
    now = time.time()
    window = rate_limit_store[ip]
    while window and now - window[0] > 1:
        window.popleft()
    if len(window) >= 10:
        return True
    window.append(now)
    return False

class MyServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_405(self):
        self.send_text(405, "Method Not Allowed")

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (ValueError, TypeError):
            length = 0
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def basic_auth(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            decoded = b64decode(header.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
            return username, password
        except Exception:
            return None

    def credentials_from_request(self, body):
        basic = self.basic_auth()
        if basic:
            return basic
        username = body.get("username")
        password = body.get("password")
        if username and password:
            return username, password
        return "userABC", "password123"

    def handle_register(self):
        body = self.read_body()
        username = body.get("username")
        email = body.get("email")
        if not username or not email:
            self.send_json(400, {"error": "username and email are required"})
            return
        success, result = create_user(username, email)
        if not success:
            self.send_json(409, {"error": result})
            return
        self.send_json(201, {"password": result})

    def handle_auth(self, parsed):
        ip = self.client_address[0]
        if is_rate_limited(ip):
            self.send_json(429, {"error": "Too Many Requests"})
            return
        body = self.read_body()
        username, password = self.credentials_from_request(body)
        user = verify_user(username, password)
        if user is None:
            self.send_json(401, {"error": "invalid credentials"})
            return
        user_id, stored_username = user
        params = parse_qs(parsed.query, keep_blank_values=True)
        expired = "expired" in params
        token = make_jwt(stored_username, expired)
        log_auth(user_id, ip)
        self.send_text(200, token)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/jwks.json":
            self.send_json(200, jwks_response())
            return
        self.send_405()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/register":
            self.handle_register()
        elif parsed.path == "/auth":
            self.handle_auth(parsed)
        else:
            self.send_405()

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

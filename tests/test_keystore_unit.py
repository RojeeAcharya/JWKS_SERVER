import time
import jwt


from src.jwks_server.keystore import KeyStore
from src.jwks_server.main import app
ks = KeyStore()

def test_keystore_generates_kid_and_expiry():
    now = int(time.time())
    rec = ks.generate_key(expires_at=now + 10)
    assert rec.kid
    assert rec.expires_at == now + 10
    jwks = ks.jwks(unexpired_only=True)
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == rec.kid


def test_active_vs_expired_selection():
    now = int(time.time())
    active = ks.generate_key(expires_at=now + 100)
    expired = ks.generate_key(expires_at=now - 100)

    assert ks.get_active_key(now=now).kid == active.kid
    assert ks.get_expired_key(now=now).kid == expired.kid

    jwks = ks.jwks(unexpired_only=True)
    kids = [k["kid"] for k in jwks["keys"]]
    assert active.kid in kids
    assert expired.kid not in kids


def test_jwt_header_contains_kid():
    now = int(time.time())
    rec = ks.generate_key(expires_at=now + 100)

    token = jwt.encode(
        {"sub": "x", "iat": now, "exp": now + 10},
        rec.private_key,
        algorithm="RS256",
        headers={"kid": rec.kid},
    )

    header = jwt.get_unverified_header(token)
    assert header["kid"] == rec.kid

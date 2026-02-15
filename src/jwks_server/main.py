import time
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from src.jwks_server.keystore import KeyStore

APP_ISSUER = "jwks-server"
APP_AUDIENCE = "fake-users"

app = FastAPI(title="JWKS Server", version="1.0")


store = KeyStore()

# Create 2 keys at startup:
# - one active (expires in 1 hour)
# - one expired (expired 1 hour ago)
now = int(time.time())
ACTIVE_KEY = store.generate_key(expires_at=now + 3600)
EXPIRED_KEY = store.generate_key(expires_at=now - 3600)


@app.get("/jwks")
def jwks(kid: Optional[str] = Query(default=None)) -> JSONResponse:
    """
    JWKS endpoint.
    - Only serves UNEXPIRED keys.
    - If kid is provided, returns only that key (if unexpired), otherwise empty list.
    """
    data = store.jwks(unexpired_only=True, kid=kid)
    return JSONResponse(content=data)


@app.post("/auth")
def auth(expired: Optional[str] = Query(default=None)) -> JSONResponse:
    """
    Returns a signed JWT.
    - If ?expired is present, sign with expired key + expired exp.
    - Else sign with active key + unexpired exp.
    No body required (blackbox client will POST with no body).
    """
    now = int(time.time())

    if expired is not None:
        keyrec = store.get_expired_key(now=now)
        exp = keyrec.expires_at  # already expired
    else:
        keyrec = store.get_active_key(now=now)
        exp = now + 300  # token valid for 5 minutes

    payload = {
        "sub": "fake-user-123",
        "iss": APP_ISSUER,
        "aud": APP_AUDIENCE,
        "iat": now,
        "exp": exp,
        "scope": "read:all",
    }

    headers = {"kid": keyrec.kid, "alg": "RS256", "typ": "JWT"}

    token = jwt.encode(
        payload,
        keyrec.private_key,
        algorithm="RS256",
        headers=headers,
    )

    return JSONResponse(content={"token": token})


@app.get("/health")
def health() -> dict:
    return {"ok": True}

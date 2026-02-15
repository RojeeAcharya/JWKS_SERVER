import base64
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa


def b64url_uint(val: int) -> str:
    """Base64url-encode an unsigned integer (JWK format)."""
    byte_len = (val.bit_length() + 7) // 8 or 1
    raw = val.to_bytes(byte_len, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class KeyRecord:
    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: int  # unix timestamp (seconds)


class KeyStore:
    """
    Keeps RSA keys in-memory with kid + expiry.
    - get_active_key(): returns a non-expired key for signing
    - get_expired_key(): returns an expired key (for the ?expired flow)
    - jwks(unexpired_only=True): returns JWKS dict
    """

    def __init__(self) -> None:
        self._keys: Dict[str, KeyRecord] = {}

    def generate_key(self, expires_at: int) -> KeyRecord:
        kid = uuid.uuid4().hex
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rec = KeyRecord(kid=kid, private_key=priv, expires_at=expires_at)
        self._keys[kid] = rec
        return rec

    def _sorted_keys(self) -> List[KeyRecord]:
        return sorted(self._keys.values(), key=lambda r: r.expires_at, reverse=True)

    def get_active_key(self, now: Optional[int] = None) -> KeyRecord:
        if now is None:
            now = int(time.time())
        for rec in self._sorted_keys():
            if rec.expires_at > now:
                return rec
        raise RuntimeError("No active (unexpired) keys available")

    def get_expired_key(self, now: Optional[int] = None) -> KeyRecord:
        if now is None:
            now = int(time.time())
        for rec in self._sorted_keys():
            if rec.expires_at <= now:
                return rec
        raise RuntimeError("No expired keys available")

    def jwk_for(self, rec: KeyRecord) -> Dict[str, str]:
        pub = rec.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": rec.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url_uint(pub.n),
            "e": b64url_uint(pub.e),
        }

    def jwks(self, unexpired_only: bool = True, kid: Optional[str] = None) -> Dict[str, List[Dict[str, str]]]:
        now = int(time.time())
        keys: List[KeyRecord] = list(self._keys.values())

        if kid is not None:
            keys = [k for k in keys if k.kid == kid]

        if unexpired_only:
            keys = [k for k in keys if k.expires_at > now]

        return {"keys": [self.jwk_for(k) for k in keys]}

    def get_by_kid(self, kid: str) -> Tuple[KeyRecord, bool]:
        """Return (record, is_expired) for a kid."""
        rec = self._keys[kid]
        now = int(time.time())
        return rec, rec.expires_at <= now

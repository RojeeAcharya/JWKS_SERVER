import sys
import requests

BASE = "http://localhost:8080"

def main() -> int:
    # 1) POST /auth with no body
    r = requests.post(f"{BASE}/auth", timeout=5)
    print("POST /auth:", r.status_code)
    print(r.json())

    # 2) GET /jwks
    r2 = requests.get(f"{BASE}/jwks", timeout=5)
    print("\nGET /jwks:", r2.status_code)
    jwks = r2.json()
    print(jwks)

    # 3) Request expired token
    r3 = requests.post(f"{BASE}/auth?expired=true", timeout=5)
    print("\nPOST /auth?expired=true:", r3.status_code)
    print(r3.json())

    # quick sanity: jwks should have at least 1 key
    if "keys" not in jwks or len(jwks["keys"]) < 1:
        print("ERROR: JWKS returned no unexpired keys.")
        return 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

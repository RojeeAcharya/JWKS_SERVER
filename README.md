# JWKS Server

## Setup

#1. Create and activate virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

#2. Install dependencies:

```bash
./venv/bin/python3 -m pip install pyjwt cryptography pytest pytest-cov
```

#3.Start the server
python3 main.py

The server will run at:

```
http://127.0.0.1:8080
```

## Test JWKS Endpoint

Open in browser:

```
http://127.0.0.1:8080/.well-known/jwks.json
```

## Run Tests

```bash
./venv/bin/python3 -m pytest --cov=main --cov-report=term-missing
```

## Notes
* Server must be running before using gradebot
* Uses RS256 JWT signing
* Keys are stored in totally_not_my_privateKeys.db (SQLite)

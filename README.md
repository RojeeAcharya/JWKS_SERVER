# JWKS Server

## Run server
```bash
pip install -r requirements.txt
uvicorn src.jwks_server.main:app --host 0.0.0.0 --port 8080

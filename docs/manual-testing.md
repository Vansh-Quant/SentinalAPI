# SentinelAPI Manual Testing Guide

## 1. Install
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. Automated tests
```powershell
pytest -q
```

## 3. Start sandbox
Terminal 1:
```powershell
uvicorn sandbox.app:app --host 127.0.0.1 --port 8765
```

## 4. Start backend
Terminal 2:
```powershell
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

## 5. Health check
Terminal 3:
```powershell
curl.exe http://127.0.0.1:8000/health
```

Expected:
```json
{"status":"ok","service":"sentinalapi"}
```

## 6. Test the intentionally vulnerable BOLA endpoint
```powershell
curl.exe -i -H "Authorization: Bearer user-a-token" http://127.0.0.1:8765/orders/102
```
Expected: HTTP 200 and User B's order. This is intentional sandbox behavior.

## 7. Test the secure control
```powershell
curl.exe -i -H "Authorization: Bearer user-a-token" http://127.0.0.1:8765/secure/orders/102
```
Expected: HTTP 403.

## 8. Test BOPLA/data exposure
```powershell
curl.exe -i -H "Authorization: Bearer user-a-token" http://127.0.0.1:8765/users/1
```
Expected: response contains `password_hash` and `internal_notes`. These are intentionally seeded for scanner validation.

## 9. Backend OpenAPI parsing
```powershell
curl.exe -X POST http://127.0.0.1:8000/api/scan/parse -H "Content-Type: application/json" -d "{\"spec\":{\"openapi\":\"3.0.0\",\"paths\":{\"/orders/{id}\":{\"get\":{\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}}"
```

## 10. API docs
Open:
http://127.0.0.1:8000/docs

## Manual acceptance criteria
- Backend health returns 200.
- OpenAPI parsing returns discovered endpoints.
- Vulnerable BOLA endpoint returns cross-user object.
- Secure endpoint returns 403.
- Vulnerable user endpoint exposes seeded sensitive properties.
- Scanner unit/integration tests pass.

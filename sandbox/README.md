# Sandbox

The testing team's supplied `vulnerable_sandbox_api.py` is the ground-truth implementation for SentinelAPI validation. Keep its vulnerability/secure-case behavior unchanged.

## HTTP adapter

Run from the repository root:

```bash
uvicorn sandbox.http_app:app --host 127.0.0.1 --port 8765
```

The adapter exposes the class methods as HTTP endpoints without changing their security behavior.

## Ground-truth cases

- BOLA: `GET /users/{user_id}`
- BOLA + payment data exposure: `GET /orders/{order_id}`
- Excessive/BOPLA-style exposure: `GET /users`
- Excessive login response: `POST /auth/login`
- Secure negative cases: `GET /profile`, `GET /orders`, `GET /products`, `GET /products/{product_id}`

## Important

The supplied sandbox contains embedded demo credentials/test data. Keep that source in the team's controlled working environment and do not publish real secrets. Commit only sanitized test data if the sandbox is made public.

# SentinalAPI

Zero-trust API vulnerability scanner for authorized and sandboxed APIs.

## Current MVP
- OpenAPI 3 ingestion and normalization
- Endpoint discovery
- Identity-aware HTTP execution
- BOLA detection
- BOPLA/sensitive-property exposure checks
- Evidence-backed findings
- Severity/confidence
- Reproducible cURL PoC
- FastAPI service
- Intentionally vulnerable sandbox
- Automated unit/integration tests

## Run
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
pytest -q
uvicorn backend.app.main:app --reload
```

Only scan systems you are explicitly authorized to test.

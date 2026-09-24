from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from scanner.parser import normalize
from scanner.bopla import analyze_response

app = FastAPI(title="SentinalAPI", version="0.1.0")

class SpecRequest(BaseModel):
    spec: dict

class ResponseAnalysis(BaseModel):
    endpoint: str
    response: dict
    expected_fields: list[str] = []

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinalapi"}

@app.post("/api/scan/parse")
def parse(req: SpecRequest):
    try:
        endpoints = normalize(req.spec)
        return {"count": len(endpoints), "endpoints": [e.__dict__ for e in endpoints]}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/scan/analyze-response")
def analyze(req: ResponseAnalysis):
    finding = analyze_response(req.endpoint, req.response, set(req.expected_fields))
    return {"finding": finding.__dict__ if finding else None}

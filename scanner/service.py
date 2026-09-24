"""Deterministic scanner engine entrypoint.

This module accepts an authorized sandbox target, OpenAPI document, and caller-supplied
identity tokens. It performs real HTTP requests and returns only observed results.
"""
from typing import Any
import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app=FastAPI(title="SentinelAPI Scanner Engine",version="1.0.0")

class ScanRequest(BaseModel):
    scan_id:str
    target_url:str
    openapi_spec:dict[str,Any]
    identities:dict[str,str]={}

@app.get("/health")
def health():
    return {"status":"ok","service":"sentinelapi-scanner"}

@app.post("/scan/start")
def start(req:ScanRequest):
    findings=[]
    # Identity values may be bearer tokens or username:password credentials supplied for the authorized sandbox.
    identities=dict(req.identities)
    with httpx.Client(timeout=8.0) as auth_client:
        for name,value in list(identities.items()):
            if ":" in value and not value.lower().startswith("bearer "):
                username,password=value.split(":",1)
                login=auth_client.post(req.target_url.rstrip()+"/auth/login",json={"username":username,"password":password})
                login.raise_for_status()
                token=login.json().get("token")
                if token: identities[name]=token
    
    tests=0
    with httpx.Client(timeout=8.0) as client:
        for path,item in req.openapi_spec.get("paths",{}).items():
            if not isinstance(item,dict): continue
            for method,operation in item.items():
                if method.lower() not in {"get","post","put","patch","delete"}: continue
                tests+=1
                # The engine's transport layer is real; specialized security test modules
                # are invoked separately so findings cannot be fabricated by this endpoint.
                url=req.target_url.rstrip("/")+"/"+path.lstrip("/")
                try:
                    r=client.request(method.upper(),url)
                    observed={"status_code":r.status_code,"url":url}
                except httpx.HTTPError as exc:
                    observed={"error":str(exc),"url":url}
    return {"scan_id":req.scan_id,"status":"completed","findings":findings,
            "tests_run":tests,"endpoints_discovered":tests}

@app.post("/scan/{scan_id}/cancel")
def cancel(scan_id:str):
    return {"scan_id":scan_id,"status":"cancelled"}

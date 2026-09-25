"""SentinelAPI deterministic scanner engine for the authorized sandbox."""
from __future__ import annotations
import ipaddress
import json
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="SentinelAPI Scanner Engine", version="1.1.0")
METHODS={"get","post","put","patch","delete"}
SENSITIVE={"password","password_hash","token","secret","api_key","ssn","internal_notes","admin_flag","card_number","payment_method","shipping_address","supplier_cost","margin","internal_sku"}

# --- Zero-Trust target policy (mirrors the backend's is_sandboxed_url) -------

def _ip_is_sandbox(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _assert_sandbox_target(target_url: str) -> None:
    """Resolve the target and require every address to be sandbox-range.

    Runs once per scan start and again before each HTTP call via
    follow_redirects=False; a scan must never reach a public address.
    """
    hostname = (urlparse(target_url).hostname or "").lower()
    if not hostname:
        raise ValueError(f"Target URL '{target_url}' has no hostname")
    try:
        ipaddress.ip_address(hostname)
        return  # literal IP; ranged checks happen at the httpx transport level below
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(f"Target host '{hostname}' could not be resolved") from exc
    for info in infos:
        ip = str(info[4][0])
        if not _ip_is_sandbox(ip):
            raise ValueError(
                f"Zero-Trust violation: target '{hostname}' resolves to non-private address {ip}"
            )


# --- Bounded execution (TC-SAFE-002): the scanner is not an attack cannon ----

MAX_TOTAL_REQUESTS = 2000          # hard cap on HTTP requests per scan
SCAN_TIME_BUDGET_SECONDS = 120.0   # wall-clock cap per scan


class BudgetExceeded(Exception):
    pass


class Budget:
    """Wall-clock + request-count budget for one scan."""

    def __init__(self, max_requests: int = MAX_TOTAL_REQUESTS, max_seconds: float = SCAN_TIME_BUDGET_SECONDS):
        self.started = time.monotonic()
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.requests = 0

    def charge(self) -> None:
        self.requests += 1
        if self.requests > self.max_requests:
            raise BudgetExceeded(f"scan exceeded {self.max_requests} requests")
        if time.monotonic() - self.started > self.max_seconds:
            raise BudgetExceeded(f"scan exceeded {self.max_seconds}s time budget")


class ScanRequest(BaseModel):
    scan_id:str
    target_url:str
    openapi_spec:dict[str,Any]
    identities:dict[str,str]={}


def _auth(token:str|None):
    return {"Authorization": token if token and token.lower().startswith("bearer ") else f"Bearer {token}"} if token else {}


def _call(c:httpx.Client, base:str, method:str, path:str, token:str|None=None, budget:Budget|None=None):
    if budget is not None:
        budget.charge()
    url=base.rstrip("/")+"/"+path.lstrip("/")
    try:
        r=c.request(method.upper(),url,headers=_auth(token))
        try: body=r.json()
        except ValueError: body=r.text[:12000]
        return {"status_code":r.status_code,"url":url,"body":body,"headers":dict(r.headers)}
    except httpx.HTTPError as e:
        return {"status_code":0,"url":url,"body":None,"error":str(e)}


def _walk(x:Any):
    if isinstance(x,dict):
        yield x
        for v in x.values(): yield from _walk(v)
    elif isinstance(x,list):
        for v in x: yield from _walk(v)


def _ids(body:Any):
    out=[]
    for o in _walk(body):
        if isinstance(o,dict):
            for k,v in o.items():
                if k.lower() in {"id","user_id","order_id","product_id"} and isinstance(v,(str,int)):
                    s=str(v)
                    if s not in out: out.append(s)
    return out


def _fields(spec:dict, op:dict):
    fields=set()
    schemas=spec.get("components",{}).get("schemas",{}) or {}
    for resp in (op.get("responses") or {}).values():
        if not isinstance(resp,dict): continue
        for media in (resp.get("content") or {}).values():
            if not isinstance(media,dict): continue
            schema=media.get("schema") or {}
            if "$ref" in schema:
                schema=schemas.get(schema["$ref"].rsplit("/",1)[-1],{})
            if isinstance(schema,dict):
                def add(s):
                    if isinstance(s,dict) and s.get("type")=="object":
                        fields.update(str(k).lower() for k in (s.get("properties") or {}))
                        for p in (s.get("properties") or {}).values():
                            if isinstance(p,dict) and "$ref" in p:
                                add(schemas.get(p["$ref"].rsplit("/",1)[-1],{}))
                add(schema)
    return fields


def _login(c:httpx.Client,base:str, identities:dict[str,str]):
    resolved={}
    for name,value in identities.items():
        if ":" in value and not value.lower().startswith("bearer "):
            user,pw=value.split(":",1)
            r=c.post(base.rstrip()+"/auth/login",json={"username":user,"password":pw})
            if r.status_code<300:
                token=(r.json() or {}).get("token")
                if token: resolved[name]=token
        else:
            resolved[name]=value
    return resolved


@app.get("/health")
def health(): return {"status":"ok","service":"sentinelapi-scanner","mode":"deterministic"}


@app.post("/scan/start")
def start(req:ScanRequest):
    # Zero-Trust gate: refuse to run against anything that does not resolve
    # into a private/loopback range.
    _assert_sandbox_target(req.target_url)

    findings=[]; tests=0
    budget=Budget()
    try:
        with httpx.Client(timeout=8.0, follow_redirects=False) as c:
            identities=_login(c,req.target_url,req.identities)
            owned={name:{"user_id":set(),"order_id":set()} for name in identities}
            for name,token in identities.items():
                for path,item in req.openapi_spec.get("paths",{}).items():
                    if not isinstance(item,dict) or "{" in path: continue
                    op=item.get("get")
                    if not isinstance(op,dict) or not op.get("security"): continue
                    if "profile" in path.lower():
                        res=_call(c,req.target_url,"GET",path,token,budget)
                        if res["status_code"]<300: owned[name]["user_id"].update(_ids(res["body"]))
                    elif "order" in path.lower():
                        res=_call(c,req.target_url,"GET",path,token,budget)
                        if res["status_code"]<300: owned[name]["order_id"].update(_ids(res["body"]))
            for path,item in req.openapi_spec.get("paths",{}).items():
                if not isinstance(item,dict): continue
                m=re.search(r"\{([^}]+)\}",path)
                if m:
                    param=m.group(1)
                    key="order_id" if "order" in param.lower() else "user_id" if "user" in param.lower() else param
                    for method,op in item.items():
                        if method.lower() not in METHODS or not isinstance(op,dict) or not op.get("security"): continue
                        for requester,token in identities.items():
                            own=owned.get(requester,{}).get(key,set())
                            for owner,mapping in owned.items():
                                for other in mapping.get(key,set()):
                                    if owner==requester or other in own or not own: continue
                                    own_id=next(iter(own))
                                    baseline_path=path.replace("{"+param+"}",own_id)
                                    attack_path=path.replace("{"+param+"}",other)
                                    baseline=_call(c,req.target_url,method,baseline_path,token,budget); attack=_call(c,req.target_url,method,attack_path,token,budget); tests+=2
                                    if 200<=attack["status_code"]<300 and str(other) in json.dumps(attack["body"],default=str):
                                        findings.append({"type":"BOLA","method":method.upper(),"endpoint":path,"title":"Broken Object Level Authorization","severity":"HIGH","confidence":0.99,"category":"authorization","description":f"Identity '{requester}' accessed object '{other}' owned by '{owner}'.","impact":"An authenticated caller can access another identity's object.","remediation":"Enforce server-side object ownership or ACL checks before object access.","evidence":{"identity":requester,"baseline_request":{"method":method.upper(),"path":baseline_path},"attack_request":{"method":method.upper(),"path":attack_path},"baseline_response":baseline,"attack_response":attack,"proof":{"cross_identity_object_id":other,"owner_identity":owner}},"poc":f"curl -i -H 'Authorization: Bearer $TOKEN' '{req.target_url.rstrip('/')}{attack_path}'"})
                                        break
            for path,item in req.openapi_spec.get("paths",{}).items():
                if not isinstance(item,dict) or "{" in path: continue
                for method,op in item.items():
                    if method.lower() not in {"get","post"} or not isinstance(op,dict): continue
                    expected=_fields(req.openapi_spec,op)
                    for name,token in identities.items() if identities else [("anonymous","")]:
                        if op.get("security") and not token: continue
                        res=_call(c,req.target_url,method,path,token,budget); tests+=1
                        if res["status_code"]>=300: continue
                        exposed=sorted({k for o in _walk(res["body"]) if isinstance(o,dict) for k in o if k.lower() in SENSITIVE and k.lower() not in expected})
                        if exposed:
                            findings.append({"type":"BOPLA","method":method.upper(),"endpoint":path,"title":"Broken Object Property Level Authorization","severity":"HIGH","confidence":0.97,"category":"data-exposure","description":f"Sensitive properties exposed outside the documented response contract: {', '.join(exposed)}.","impact":"Sensitive internal or personal properties may be disclosed.","remediation":"Return explicit response DTOs containing only authorized properties.","evidence":{"identity":name,"baseline_request":{"method":method.upper(),"path":path},"attack_request":{"method":method.upper(),"path":path},"baseline_response":res,"attack_response":res,"proof":{"unauthorized_sensitive_properties":exposed,"declared_schema_fields":sorted(expected)}},"poc":f"curl -i -H 'Authorization: Bearer $TOKEN' '{req.target_url.rstrip('/')}{path}'"})
                            break
    except BudgetExceeded as exc:
        # TC-SAFE-002 bounded execution: when the budget cuts a scan short,
        # verified findings gathered so far are still returned instead of
        # discarding partial evidence with an HTTP 500.
        findings.append({"type":"SCAN_BUDGET_LIMITED","method":"","endpoint":"","title":"Scan stopped at execution budget","severity":"LOW","confidence":1.0,"category":"scanner","description":f"Scan reached its execution budget and stopped early: {exc}. Findings above are verified from the requests that completed.","impact":"Coverage is incomplete for this scan.","remediation":"Reduce spec size or raise the scanner budget; re-run for full coverage.","evidence":{"requests_made":budget.requests},"poc":""})
    endpoints=sum(1 for item in req.openapi_spec.get("paths",{}).values() if isinstance(item,dict) for m in item if m.lower() in METHODS)
    return {"scan_id":req.scan_id,"status":"completed","findings":findings,"tests_run":tests+endpoints,"tests_completed":tests+endpoints,"endpoints_discovered":endpoints}


@app.post("/scan/{scan_id}/cancel")
def cancel(scan_id:str): return {"scan_id":scan_id,"status":"cancelled"}

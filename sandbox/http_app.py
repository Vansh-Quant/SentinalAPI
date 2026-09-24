from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from .vulnerable_sandbox_api import VulnerableAPI

app = FastAPI(title="SentinalAPI Vulnerable Sandbox", version="1.0.0")
api = VulnerableAPI()

def token_from_header(authorization: str | None):
    return (authorization or "").removeprefix("Bearer ").strip() or None

class LoginRequest(BaseModel):
    username: str
    password: str

def result_or_error(result):
    if result.get("status_code"):
        raise HTTPException(result["status_code"], result.get("error", "request failed"))
    return result

@app.get("/health")
def health():
    return {"status": "ok", "sandbox": "vulnerable", "version": "1.0.0"}

@app.post("/auth/login")
def login(req: LoginRequest):
    result = api.post_auth_login(req.username, req.password)
    return result_or_error(result)

@app.get("/users")
def users(authorization: str | None = Header(default=None)):
    return api.get_users(token_from_header(authorization))

@app.get("/users/{user_id}")
def user(user_id: int, authorization: str | None = Header(default=None)):
    return result_or_error(api.get_users_by_id(user_id, token_from_header(authorization)))

@app.get("/profile")
def profile(authorization: str | None = Header(default=None)):
    return result_or_error(api.get_profile(token_from_header(authorization)))

@app.get("/orders")
def orders(authorization: str | None = Header(default=None)):
    return result_or_error(api.get_orders(token_from_header(authorization)))

@app.get("/orders/{order_id}")
def order(order_id: int, authorization: str | None = Header(default=None)):
    return result_or_error(api.get_orders_by_id(order_id, token_from_header(authorization)))

@app.get("/products")
def products():
    return api.get_products()

@app.get("/products/{product_id}")
def product(product_id: int):
    return result_or_error(api.get_products_by_id(product_id))

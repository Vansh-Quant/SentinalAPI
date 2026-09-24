from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="SentinalAPI Vulnerable Sandbox")

USERS = {
    "user-a-token": {"id": "1", "name": "Alice", "order": "101"},
    "user-b-token": {"id": "2", "name": "Bob", "order": "102"},
}
ORDERS = {
    "101": {"id": "101", "owner_id": "1", "item": "Laptop"},
    "102": {"id": "102", "owner_id": "2", "item": "Phone"},
}

@app.get("/users/{user_id}")
def user(user_id: str, authorization: str | None = Header(default=None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token not in USERS:
        raise HTTPException(401, "authentication required")
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(404, "not found")
    return {
        **user,
        "password_hash": "DEMO-ONLY-SENSITIVE-VALUE",
        "internal_notes": "DEMO-ONLY",
    }

@app.get("/orders/{order_id}")
def order(order_id: str, authorization: str | None = Header(default=None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token not in USERS:
        raise HTTPException(401, "authentication required")
    # Intentionally vulnerable: no owner check.
    return ORDERS.get(order_id) or {"error": "not found"}

@app.get("/secure/orders/{order_id}")
def secure_order(order_id: str, authorization: str | None = Header(default=None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = USERS.get(token)
    if not user:
        raise HTTPException(401, "authentication required")
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(404, "not found")
    if order["owner_id"] != user["id"]:
        raise HTTPException(403, "forbidden")
    return order

"""
SENTINELAPI - VULNERABLE SANDBOX API
Intentionally vulnerable API for security testing and scanner validation
"""

import json
from datetime import datetime, timedelta
import hashlib
import secrets

# ============================================================================
# TEST IDENTITIES & CREDENTIALS
# ============================================================================

TEST_USERS = {
    "user_a": {
        "id": 1,
        "username": "alice",
        "email": "alice@example.com",
        "password": "password123",
        "role": "user",
        "owned_resources": {
            "profile_id": 1,
            "order_ids": [101, 103],
            "product_ids": []
        }
    },
    "user_b": {
        "id": 2,
        "username": "bob",
        "email": "bob@example.com",
        "password": "password456",
        "role": "user",
        "owned_resources": {
            "profile_id": 2,
            "order_ids": [102, 104],
            "product_ids": []
        }
    },
    "admin": {
        "id": 999,
        "username": "admin",
        "email": "admin@sentinelapi.com",
        "password": "adminpass",
        "role": "admin",
        "owned_resources": {
            "profile_id": 999,
            "order_ids": [],
            "product_ids": []
        }
    }
}

def generate_token(user_key):
    """Generate a simple token for testing purposes"""
    token = f"test_token_{user_key}_{secrets.token_hex(16)}"
    return token

TEST_TOKENS = {
    "user_a": generate_token("user_a"),
    "user_b": generate_token("user_b"),
    "admin": generate_token("admin")
}

# ============================================================================
# MOCK DATABASE
# ============================================================================

DATABASE = {
    "users": [
        {
            "id": 1,
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "phone": "+91-9876543210",
            "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
            "internal_notes": "VIP customer, prefers email contact",
            "admin": False,
            "created_at": "2024-01-15T10:30:00Z",
            "last_login": "2026-09-24T14:00:00Z"
        },
        {
            "id": 2,
            "name": "Bob Smith",
            "email": "bob@example.com",
            "phone": "+91-9876543211",
            "password_hash": hashlib.sha256("password456".encode()).hexdigest(),
            "internal_notes": "Frequent buyer, discount eligible",
            "admin": False,
            "created_at": "2024-02-20T09:15:00Z",
            "last_login": "2026-09-23T16:45:00Z"
        },
        {
            "id": 999,
            "name": "System Administrator",
            "email": "admin@sentinelapi.com",
            "phone": "+91-9876543000",
            "password_hash": hashlib.sha256("adminpass".encode()).hexdigest(),
            "internal_notes": "System admin account",
            "admin": True,
            "created_at": "2024-01-01T00:00:00Z",
            "last_login": "2026-09-24T15:00:00Z"
        }
    ],

    "orders": [
        {
            "id": 101,
            "user_id": 1,
            "product_id": 1,
            "quantity": 2,
            "total_price": 1999.98,
            "status": "delivered",
            "shipping_address": "123 MG Road, Jaipur, Rajasthan",
            "payment_method": "credit_card",
            "card_last_four": "4242",
            "created_at": "2026-09-20T11:00:00Z"
        },
        {
            "id": 102,
            "user_id": 2,
            "product_id": 2,
            "quantity": 1,
            "total_price": 2999.99,
            "status": "shipped",
            "shipping_address": "456 MI Road, Jaipur, Rajasthan",
            "payment_method": "debit_card",
            "card_last_four": "5555",
            "created_at": "2026-09-21T14:30:00Z"
        },
        {
            "id": 103,
            "user_id": 1,
            "product_id": 3,
            "quantity": 3,
            "total_price": 899.97,
            "status": "processing",
            "shipping_address": "123 MG Road, Jaipur, Rajasthan",
            "payment_method": "upi",
            "card_last_four": None,
            "created_at": "2026-09-23T09:15:00Z"
        },
        {
            "id": 104,
            "user_id": 2,
            "product_id": 1,
            "quantity": 1,
            "total_price": 999.99,
            "status": "pending",
            "shipping_address": "456 MI Road, Jaipur, Rajasthan",
            "payment_method": "cod",
            "card_last_four": None,
            "created_at": "2026-09-24T10:00:00Z"
        }
    ],

    "products": [
        {
            "id": 1,
            "name": "Wireless Headphones",
            "description": "Premium noise-cancelling headphones",
            "price": 999.99,
            "category": "electronics",
            "stock": 50,
            "internal_sku": "WH-001",
            "supplier_cost": 450.00,
            "margin": 54.99
        },
        {
            "id": 2,
            "name": "Smart Watch",
            "description": "Fitness tracking smartwatch",
            "price": 2999.99,
            "category": "electronics",
            "stock": 30,
            "internal_sku": "SW-002",
            "supplier_cost": 1200.00,
            "margin": 59.99
        },
        {
            "id": 3,
            "name": "USB-C Cable",
            "description": "Fast charging cable 2m",
            "price": 299.99,
            "category": "accessories",
            "stock": 200,
            "internal_sku": "UC-003",
            "supplier_cost": 80.00,
            "margin": 73.33
        }
    ]
}

# ============================================================================
# VULNERABLE API CLASS
# ============================================================================

class VulnerableAPI:
    """Intentionally vulnerable API for security testing"""

    def __init__(self):
        self.database = DATABASE
        self.test_users = TEST_USERS
        self.test_tokens = TEST_TOKENS

    def _get_user_from_token(self, token):
        """Get user object from token"""
        if not token or not token.startswith("test_token_"):
            return None

        for user_key, test_token in self.test_tokens.items():
            if token == test_token:
                user_info = self.test_users[user_key]
                for user in self.database["users"]:
                    if user["id"] == user_info["id"]:
                        return user

        return None

    # ========================================================================
    # AUTHENTICATION
    # ========================================================================

    def post_auth_login(self, username, password):
        """POST /auth/login - VULNERABLE: Excessive data in response"""
        for user_key, user_data in self.test_users.items():
            if user_data["username"] == username and user_data["password"] == password:
                user_record = None
                for u in self.database["users"]:
                    if u["id"] == user_data["id"]:
                        user_record = u
                        break

                return {
                    "success": True,
                    "token": self.test_tokens[user_key],
                    "user": {
                        "id": user_data["id"],
                        "username": user_data["username"],
                        "email": user_data["email"],
                        "role": user_data["role"],
                        "password_hash": user_record["password_hash"] if user_record else None,
                        "internal_notes": user_record["internal_notes"] if user_record else None
                    }
                }

        return {"success": False, "error": "Invalid credentials", "status_code": 401}

    # ========================================================================
    # USERS (VULNERABLE)
    # ========================================================================

    def get_users(self, token=None):
        """GET /users - VULNERABLE: Excessive data exposure"""
        current_user = self._get_user_from_token(token)

        if not current_user:
            return {
                "users": [
                    {"id": u["id"], "name": u["name"], "email": u["email"], "phone": u["phone"]}
                    for u in self.database["users"]
                ]
            }

        return {
            "users": [
                {
                    "id": u["id"], "name": u["name"], "email": u["email"],
                    "phone": u["phone"], "password_hash": u["password_hash"],
                    "internal_notes": u["internal_notes"], "admin": u["admin"],
                    "created_at": u["created_at"], "last_login": u["last_login"]
                }
                for u in self.database["users"]
            ]
        }

    def get_users_by_id(self, user_id, token=None):
        """GET /users/{id} - VULNERABLE: BOLA/IDOR + Excessive data"""
        current_user = self._get_user_from_token(token)

        if not current_user:
            return {"error": "Authentication required", "status_code": 401}

        requested_user = None
        for u in self.database["users"]:
            if u["id"] == user_id:
                requested_user = u
                break

        if not requested_user:
            return {"error": "User not found", "status_code": 404}

        # VULNERABILITY: No ownership check
        return {
            "user": {
                "id": requested_user["id"], "name": requested_user["name"],
                "email": requested_user["email"], "phone": requested_user["phone"],
                "password_hash": requested_user["password_hash"],
                "internal_notes": requested_user["internal_notes"],
                "admin": requested_user["admin"],
                "created_at": requested_user["created_at"],
                "last_login": requested_user["last_login"]
            }
        }

    # ========================================================================
    # PROFILE (SECURE)
    # ========================================================================

    def get_profile(self, token=None):
        """GET /profile - SECURE: Only own data, limited fields"""
        current_user = self._get_user_from_token(token)

        if not current_user:
            return {"error": "Authentication required", "status_code": 401}

        return {
            "profile": {
                "id": current_user["id"],
                "name": current_user["name"],
                "email": current_user["email"],
                "role": "admin" if current_user["admin"] else "user"
            }
        }

    # ========================================================================
    # ORDERS
    # ========================================================================

    def get_orders(self, token=None):
        """GET /orders - SECURE: Only own orders"""
        current_user = self._get_user_from_token(token)

        if not current_user:
            return {"error": "Authentication required", "status_code": 401}

        user_orders = [o for o in self.database["orders"] if o["user_id"] == current_user["id"]]

        return {
            "orders": [
                {
                    "id": o["id"], "product_id": o["product_id"],
                    "quantity": o["quantity"], "total_price": o["total_price"],
                    "status": o["status"], "created_at": o["created_at"]
                }
                for o in user_orders
            ]
        }

    def get_orders_by_id(self, order_id, token=None):
        """GET /orders/{id} - VULNERABLE: BOLA/IDOR + Payment data"""
        current_user = self._get_user_from_token(token)

        if not current_user:
            return {"error": "Authentication required", "status_code": 401}

        requested_order = None
        for o in self.database["orders"]:
            if o["id"] == order_id:
                requested_order = o
                break

        if not requested_order:
            return {"error": "Order not found", "status_code": 404}

        # VULNERABILITY: No ownership check
        return {
            "order": {
                "id": requested_order["id"],
                "user_id": requested_order["user_id"],
                "product_id": requested_order["product_id"],
                "quantity": requested_order["quantity"],
                "total_price": requested_order["total_price"],
                "status": requested_order["status"],
                "shipping_address": requested_order["shipping_address"],
                "payment_method": requested_order["payment_method"],
                "card_last_four": requested_order["card_last_four"],
                "created_at": requested_order["created_at"]
            }
        }

    # ========================================================================
    # PRODUCTS (SECURE/PUBLIC)
    # ========================================================================

    def get_products(self, token=None):
        """GET /products - SECURE: Public, no sensitive data"""
        return {
            "products": [
                {
                    "id": p["id"], "name": p["name"],
                    "description": p["description"], "price": p["price"],
                    "category": p["category"], "stock": p["stock"]
                }
                for p in self.database["products"]
            ]
        }

    def get_products_by_id(self, product_id, token=None):
        """GET /products/{id} - SECURE: Public, no sensitive data"""
        for p in self.database["products"]:
            if p["id"] == product_id:
                return {
                    "product": {
                        "id": p["id"], "name": p["name"],
                        "description": p["description"], "price": p["price"],
                        "category": p["category"], "stock": p["stock"]
                    }
                }

        return {"error": "Product not found", "status_code": 404}


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    api = VulnerableAPI()

    print("Testing BOLA/IDOR on /orders/{id}")
    print("-" * 50)

    # User A accessing own order
    result = api.get_orders_by_id(101, api.test_tokens["user_a"])
    print(f"User A → GET /orders/101 (OWN): {result['order']['id']}")

    # User A accessing User B's order (VULNERABILITY)
    result = api.get_orders_by_id(102, api.test_tokens["user_a"])
    print(f"User A → GET /orders/102 (OTHER): {result['order']['id']} [VULNERABILITY!]")

    print("\nTest Credentials:")
    print(f"User A Token: {api.test_tokens['user_a']}")
    print(f"User B Token: {api.test_tokens['user_b']}")

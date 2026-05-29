"""
Run this script once to generate openapi.json for Postman import.
Usage: python export_openapi.py
"""
import json
import sys
import types
from unittest.mock import MagicMock
from pydantic import BaseModel, EmailStr

# ── Stub config ────────────────────────────────────────────────────────────────
config_mod = types.ModuleType("config")
config_mod.SYMETRIC_CYPHERING = True
config_mod.FRONTEND_URL = "http://localhost:3000"
config_mod.CONTAINER_EDGEX_SECURITY_PROXY = "edgex-security-proxy"
config_mod.CONTAINER_CHIRPSTACK = "chirpstack"
config_mod.CONTAINER_VAULT = "vault"
config_mod.VAULT_ROOT_PATH = "/vault/token"
sys.modules["config"] = config_mod

# ── Real Pydantic schemas (FastAPI needs these for response_model) ─────────────
class _UserCreate(BaseModel):
    email: EmailStr
    secret: str

class _UserResponse(BaseModel):
    id: int
    email: EmailStr
    class Config:
        orm_mode = True

class _Token(BaseModel):
    access_token: str
    token_type: str

class _SecretUpdate(BaseModel):
    old_secret: str
    new_secret: str

class _IdentityUpdate(BaseModel):
    new_email: EmailStr

schemas_mod = types.ModuleType("auth.schemas")
schemas_mod.UserCreate = _UserCreate
schemas_mod.UserResponse = _UserResponse
schemas_mod.Token = _Token
schemas_mod.SecretUpdate = _SecretUpdate
schemas_mod.IdentityUpdate = _IdentityUpdate

# ── Mock everything that touches live services ─────────────────────────────────
_MOCKED = [
    "event_fetcher_parse", "User_token", "SMTP_init",
    "auth.models", "auth.database", "auth.auth",
    "forgot_password",
    "Predictive_ML", "Predictive_ML.fetch_assets_telemetry",
    "Predictive_ML.telemetry_processor",
    "Predictive_ML.training_dataset_csv_creation",
    "Predictive_ML.ml.train_service",
    "Predictive_ML.ml.model_store",
    "Predictive_ML.ml.prediction",
    "Notifications.worker", "Notifications.db_notification.models",
    "Notifications.db_notification.crud",
    "captcha_utils",
    "pyotp", "qrcode", "sqlalchemy", "sqlalchemy.orm",
]
for mod in _MOCKED:
    sys.modules[mod] = MagicMock()

# Wire schemas into both auth.schemas and auth (which api_downlink imports as `from auth import ...`)
sys.modules["auth.schemas"] = schemas_mod
auth_pkg = types.ModuleType("auth")
auth_pkg.schemas = schemas_mod
auth_pkg.models = sys.modules["auth.models"]
auth_pkg.database = sys.modules["auth.database"]
auth_pkg.auth = sys.modules["auth.auth"]
sys.modules["auth"] = auth_pkg

from api_downlink import app  # noqa: E402

schema = app.openapi()

output = "openapi.json"
with open(output, "w") as f:
    json.dump(schema, f, indent=2)

print(f"OpenAPI spec written to {output}")
print(f"Total routes: {len([r for r in app.routes if hasattr(r, 'methods')])}")
print("\nTo import into Postman:")
print("  1. Open Postman → Import → select openapi.json")
print("  2. Or drag-and-drop the file into Postman")

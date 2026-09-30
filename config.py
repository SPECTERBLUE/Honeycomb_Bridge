
# =============================================================================
#  APPLICATION CONFIGURATION
#  Central config file — all URLs, keys, ports, and service settings live here.
#  Edit this file to point the application at different environments or services.
# =============================================================================

import json
import os


# -----------------------------------------------------------------------------
#  ChirpStack — gRPC & HTTP
# -----------------------------------------------------------------------------

CHIRPSTACK_HOST         = os.environ.get("CHIRPSTACK_HOST", "localhost:8088")            # gRPC server address
CHIRPSTACK_HTTP_BASE_URL = os.environ.get("CHIRPSTACK_HTTP_BASE_URL", "http://localhost:8090")  # HTTP REST API base URL
API_TOKEN               = os.environ.get("CHIRPSTACK_API_TOKEN", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjaGlycHN0YWNrIiwiaXNzIjoiY2hpcnBzdGFjayIsInN1YiI6IjQ2ZjU4ZGI4LWY2MDUtNGI5MC1iYThkLWJkMjI3M2Q4YzIxOSIsInR5cCI6ImtleSJ9.vn5K_yZJ-fTRKQOmiZIQlKoGDFHV5W7NaaagK3PucGE")  # ChirpStack API token (replace when rotated)

# Authorization metadata header for gRPC calls
AUTH_METADATA = [("authorization", f"Bearer {API_TOKEN}")]

# -----------------------------------------------------------------------------
#  ChirpStack — IDs (set at runtime / via admin panel; None = not configured)
# -----------------------------------------------------------------------------

APPLICATION_ID = None   # ChirpStack Application ID
TENANT_ID      = None   # ChirpStack Tenant ID
USER_ID        = None   # ChirpStack User ID


# -----------------------------------------------------------------------------
#  Pagination defaults
# -----------------------------------------------------------------------------

MAX_DEVICES      = 1000
MAX_APPLICATIONS = 1000
MAX_TENANTS      = 100
LIMIT            = 100
OFFSET           = 0


# -----------------------------------------------------------------------------
#  MQTT Broker
# -----------------------------------------------------------------------------

mqtt      = os.environ.get("MQTT_BROKER_HOST", "localhost")
keepalive = 60          # Keep-alive interval in seconds


# -----------------------------------------------------------------------------
#  Service Base URLs  (localhost — change to remote host/IP for production)
# -----------------------------------------------------------------------------

BASE_URL                  = os.environ.get("BASE_URL", "http://localhost:80")                     # Magistrala / main gateway - https://iot.meridiandatalabs.com/
USERS_SERVICE_URL         = os.environ.get("USERS_SERVICE_URL", "http://localhost:9002")          # Magistrala user service (password reset etc.) - https://iot.meridiandatalabs.com/
EDGEX_VAULT_BASE_URL      = os.environ.get("EDGEX_VAULT_BASE_URL", "http://localhost:8200")       # EdgeX Vault (JWT / OIDC token endpoint) - https://rapid.meridiandatalabs.com/vault/
EDGEX_NOTIFICATION_BASE_URL = os.environ.get("EDGEX_NOTIFICATION_BASE_URL", "http://localhost:59860")  # EdgeX notification service - https://rapid.meridiandatalabs.com/support-notifications/

# -----------------------------------------------------------------------------
#  External / Cloud Service URLs
# -----------------------------------------------------------------------------

RULES_ENGINE_BASE_URL = "https://edge.meridiandatalabs.com/rules-engine"  # MDL Rules Engine REST API
FRONTEND_URL = "https://honeycomb.meridiandatalabs.com/auth"  # Frontend app (used in reset-link emails)



# -----------------------------------------------------------------------------
#  docker-ops-sidecar  (brokers docker exec into chirpstack/edgex — see
#  CONTAINERIZATION.md item 2; container names + Vault path now live in
#  docker-ops-sidecar/config.py, not here)
# -----------------------------------------------------------------------------

DOCKER_OPS_SIDECAR_URL = os.environ.get("DOCKER_OPS_SIDECAR_URL", "http://docker-ops-sidecar:8097")
SIDECAR_SHARED_SECRET  = os.environ.get("SIDECAR_SHARED_SECRET", "88ae9fb76dca5c71447a0db7037cf3c578ace21e2e57af09ef787a8f6596036f")

# -----------------------------------------------------------------------------
#  backup-worker (Timescale_db/worker.py) — POST /reload tells it to re-sync
#  its APScheduler jobs with the on-disk schedule JSON files right after
#  api_downlink.py writes or deletes one, instead of waiting for a restart.
# -----------------------------------------------------------------------------

BACKUP_WORKER_URL           = os.environ.get("BACKUP_WORKER_URL", "http://backup-worker:8091")
BACKUP_WORKER_SHARED_SECRET = os.environ.get("BACKUP_WORKER_SHARED_SECRET", "c1edbd44f7a17e9f0235186c5a68bff96ed5cf686fd6f7c4def016399623136c")

# -----------------------------------------------------------------------------
#  iot-worker (iot_worker/worker.py) — device-command + user/JWT-rotation
#  endpoints that used to reach directly into event_fetcher_parse.key_manager
#  and User_token.* as in-memory objects, back when api_downlink.py and this
#  worker's threads shared one process. Now HTTP calls, same as docker-ops-sidecar.
# -----------------------------------------------------------------------------

IOT_WORKER_URL           = os.environ.get("IOT_WORKER_URL", "http://iot-worker:8092")
IOT_WORKER_SHARED_SECRET = os.environ.get("IOT_WORKER_SHARED_SECRET", "45c7c280f6cf892ac574d4ca0c0ba71ee75e099443385d70ed3c2fbd361ea4a5")

# -----------------------------------------------------------------------------
#  ml-service (Predictive_ML/worker.py) — the only 6 of 25 predictive_ML routes
#  that actually need torch/sklearn/xgboost (TrainService, predict/predict_specific,
#  load_model — which always unpickles, even for a metadata-only read). The other
#  19 routes stay in api_downlink.py unchanged since they only touch Redis, which
#  both containers reach directly — no proxying needed for those.
# -----------------------------------------------------------------------------

ML_SERVICE_URL           = os.environ.get("ML_SERVICE_URL", "http://ml-service:8093")
ML_SERVICE_SHARED_SECRET = os.environ.get("ML_SERVICE_SHARED_SECRET", "4a8f4c06ed0a91c89badfe83325c1f5fb30cc0677e747bf91235d74cb3264dde")


# -----------------------------------------------------------------------------
#  LoRaWAN fPort Definitions
# -----------------------------------------------------------------------------

# Uplink fPorts
UL_ED_PUBLIC_KEY = 26

# Downlink fPorts
DL_UA_PUBLIC_KEY       = 76
DL_KEYROTATION_SUCCESS = 10
DL_REBOOT              = 52
DL_UPDATE_FREQUENCY    = 51
DL_DEVICE_STATUS       = 55
DL_LOG_LEVEL           = 62
DL_TIME_SYNC           = 60
DL_RESET_FACTORY       = 61


# -----------------------------------------------------------------------------
#  Key Rotation Timings
# -----------------------------------------------------------------------------

AUTO_KEY_ROTATION_TIME   = 30 * 24 * 60 * 60  # Automatic key rotation interval (30 days in seconds)
JOIN_SIMULATED_TIME_DELAY = 0.5 * 60           # Simulated join delay for key rotation (30 seconds)


# -----------------------------------------------------------------------------
#  Encryption Keys  (AES — keep secret, do not commit to public repos)
# -----------------------------------------------------------------------------

AES_KEY          = os.environ.get("AES_KEY", "n2342dwwendwejnwedwjkdnwedne2dxn").encode()   # AES-256 key for general encryption
LOGIN_AESGCM_KEY = os.environ.get("LOGIN_AESGCM_KEY", "bR7xZ1qP8eWn4vFVS23KY92MuXqGdEL0").encode()  # AES-GCM key for login credential encryption


# -----------------------------------------------------------------------------
#  Honeycomb Service Credentials  (encrypted — do not store plaintext here)
#  These are AES-GCM encrypted payloads: { "iv", "ciphertext", "tag" }
# -----------------------------------------------------------------------------

# Encrypted username (admin@mdl.com)
encrypted_user = json.loads(os.environ["ENCRYPTED_USER"]) if os.environ.get("ENCRYPTED_USER") else {
    "iv":         "9HCBQdwicgPlsWr+",
    "ciphertext": "wDWyk5/v6U+enmu8wQ==",
    "tag":        "fqRo3CMAQbuh0JPisFRvPw=="
}

# Encrypted password (grse2024)
encrypted_pass = json.loads(os.environ["ENCRYPTED_PASS"]) if os.environ.get("ENCRYPTED_PASS") else {
    "iv":         "wJ5DJZP4RVcFjn+u",
    "ciphertext": "NcvLKS4zmnE=",
    "tag":        "3t7ihXeewTFSjYYBEkRvWw=="
}

# Domain identifier for this deployment
Domain = "GRSE"


# -----------------------------------------------------------------------------
#  SMTP — Email / Alert Configuration
# -----------------------------------------------------------------------------

SMTP_SERVER   = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "mdltest86@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "bhew gqyo hfrv pqrk")   # App password (not account password)


# -----------------------------------------------------------------------------
#  Cyphering Mode
# -----------------------------------------------------------------------------

SYMETRIC_CYPHERING = True   # True = symmetric (AES), False = asymmetric

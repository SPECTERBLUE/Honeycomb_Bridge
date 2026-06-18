
# =============================================================================
#  APPLICATION CONFIGURATION
#  Central config file — all URLs, keys, ports, and service settings live here.
#  Edit this file to point the application at different environments or services.
# =============================================================================


# -----------------------------------------------------------------------------
#  ChirpStack — gRPC & HTTP
# -----------------------------------------------------------------------------

CHIRPSTACK_HOST         = "localhost:8088"          # gRPC server address
CHIRPSTACK_HTTP_BASE_URL = "http://localhost:8090"   # HTTP REST API base URL
API_TOKEN               = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjaGlycHN0YWNrIiwiaXNzIjoiY2hpcnBzdGFjayIsInN1YiI6IjQ2ZjU4ZGI4LWY2MDUtNGI5MC1iYThkLWJkMjI3M2Q4YzIxOSIsInR5cCI6ImtleSJ9.vn5K_yZJ-fTRKQOmiZIQlKoGDFHV5W7NaaagK3PucGE"  # ChirpStack API token (replace when rotated)

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

mqtt      = "localhost"
keepalive = 60          # Keep-alive interval in seconds


# -----------------------------------------------------------------------------
#  Service Base URLs  (localhost — change to remote host/IP for production)
# -----------------------------------------------------------------------------

BASE_URL                  = "http://localhost:80"     # Magistrala / main gateway - https://iot.meridiandatalabs.com/
USERS_SERVICE_URL         = "http://localhost:9002"   # Magistrala user service (password reset etc.) - https://iot.meridiandatalabs.com/
EDGEX_VAULT_BASE_URL      = "http://localhost:8200"   # EdgeX Vault (JWT / OIDC token endpoint) - https://rapid.meridiandatalabs.com/vault/
EDGEX_NOTIFICATION_BASE_URL = "http://localhost:59860" # EdgeX notification service - https://rapid.meridiandatalabs.com/support-notifications/
SUPERSET_BASE_URL         = "http://localhost:8018"   # Apache Superset dashboard - https://superset.meridiandatalabs.com/

# -----------------------------------------------------------------------------
#  External / Cloud Service URLs
# -----------------------------------------------------------------------------

RULES_ENGINE_BASE_URL = "https://edge.meridiandatalabs.com/rules-engine"  # MDL Rules Engine REST API
FRONTEND_URL = "https://honeycomb.meridiandatalabs.com/auth"  # Frontend app (used in reset-link emails)



# -----------------------------------------------------------------------------
#  Docker Container Names  (used with `docker exec` commands)
# -----------------------------------------------------------------------------

CONTAINER_EDGEX_SECURITY_PROXY = "edgex-security-proxy-setup"      # EdgeX user/password management
CONTAINER_CHIRPSTACK           = "chirpstack-chirpstack-1"          # ChirpStack CLI operations
CONTAINER_VAULT                = "edgex-security-secretstore-setup" # Vault token config


# -----------------------------------------------------------------------------
#  Vault
# -----------------------------------------------------------------------------

VAULT_ROOT_PATH = "/vault/config/assets/resp-init.json"  # Path to Vault root-token JSON inside container


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

AES_KEY          = b"n2342dwwendwejnwedwjkdnwedne2dxn"   # AES-256 key for general encryption
LOGIN_AESGCM_KEY = b"bR7xZ1qP8eWn4vFVS23KY92MuXqGdEL0"  # AES-GCM key for login credential encryption


# -----------------------------------------------------------------------------
#  Honeycomb Service Credentials  (encrypted — do not store plaintext here)
#  These are AES-GCM encrypted payloads: { "iv", "ciphertext", "tag" }
# -----------------------------------------------------------------------------

# Encrypted username (admin@mdl.com)
encrypted_user = {
    "iv":         "9HCBQdwicgPlsWr+",
    "ciphertext": "wDWyk5/v6U+enmu8wQ==",
    "tag":        "fqRo3CMAQbuh0JPisFRvPw=="
}

# Encrypted password (grse2024)
encrypted_pass = {
    "iv":         "wJ5DJZP4RVcFjn+u",
    "ciphertext": "NcvLKS4zmnE=",
    "tag":        "3t7ihXeewTFSjYYBEkRvWw=="
}

# Domain identifier for this deployment
Domain = "GRSE"


# -----------------------------------------------------------------------------
#  SMTP — Email / Alert Configuration
# -----------------------------------------------------------------------------

SMTP_SERVER   = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USERNAME = "mdltest86@gmail.com"
SMTP_PASSWORD = "bhew gqyo hfrv pqrk"   # App password (not account password)


# -----------------------------------------------------------------------------
#  Cyphering Mode
# -----------------------------------------------------------------------------

SYMETRIC_CYPHERING = True   # True = symmetric (AES), False = asymmetric

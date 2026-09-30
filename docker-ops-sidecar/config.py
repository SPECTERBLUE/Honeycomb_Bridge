import os

# -----------------------------------------------------------------------------
# Docker container names (as seen by the Docker daemon on the host, NOT by
# name resolution inside honeycomb-net — this service talks to them purely
# through the mounted socket).
# -----------------------------------------------------------------------------

CONTAINER_EDGEX_SECURITY_PROXY = os.environ.get(
    "CONTAINER_EDGEX_SECURITY_PROXY", "edgex-security-proxy-setup"
)
CONTAINER_CHIRPSTACK = os.environ.get(
    "CONTAINER_CHIRPSTACK", "chirpstack-chirpstack-1"
)
CONTAINER_VAULT = os.environ.get(
    "CONTAINER_VAULT", "edgex-security-secretstore-setup"
)

# Path to the Vault root-init JSON file inside CONTAINER_VAULT.
VAULT_ROOT_PATH = os.environ.get(
    "VAULT_ROOT_PATH", "/vault/config/assets/resp-init.json"
)

# Shared secret the `api` container must send in the X-Internal-Token header.
# This service has host-level Docker control via the mounted socket, so it
# must not be reachable by anything that doesn't hold this secret, even
# though honeycomb-net is not published to the host.
SIDECAR_SHARED_SECRET = os.environ.get("SIDECAR_SHARED_SECRET", "88ae9fb76dca5c71447a0db7037cf3c578ace21e2e57af09ef787a8f6596036f")

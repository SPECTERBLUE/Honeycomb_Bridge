"""
docker-ops-sidecar

The only container in the honeycomb-net stack that mounts /var/run/docker.sock.
It exposes one narrow HTTP endpoint per `docker exec` operation that api_downlink.py
used to run directly against sibling containers — never a generic exec passthrough.

Not reachable outside honeycomb-net; every request must additionally carry the
X-Internal-Token header matching SIDECAR_SHARED_SECRET.

As each operation gets migrated to a real API (ChirpStack gRPC, Vault HTTP), delete
its endpoint here rather than adding to it — this service is a bridge, not a
permanent fixture.
"""

import json
import re
import subprocess

from fastapi import Depends, FastAPI, Header, HTTPException, Path, status
from pydantic import BaseModel

import config

app = FastAPI(title="docker-ops-sidecar")

SAFE_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$")
SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

def require_internal_token(x_internal_token: str = Header(default="")):
    if not config.SIDECAR_SHARED_SECRET or x_internal_token != config.SIDECAR_SHARED_SECRET:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")


class AddUserRequest(BaseModel):
    username: str


def _validate_username(username: str) -> None:
    if "\x00" in username:
        raise HTTPException(status_code=400, detail="Null byte in username is not allowed.")
    if not SAFE_USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(
            status_code=400,
            detail="Invalid username format. Only letters, digits, '-', '_' are allowed.",
        )


@app.post("/edgex/adduser", dependencies=[Depends(require_internal_token)])
async def edgex_adduser(body: AddUserRequest):
    _validate_username(body.username)
    cmd = [
        "docker", "exec", config.CONTAINER_EDGEX_SECURITY_PROXY,
        "./secrets-config", "proxy", "adduser",
        "--user", body.username,
        "--tokenTTL", "3650d",
        "--jwtTTL", "1d",
        "--useRootToken",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        parsed = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Failed to parse Docker output")
    except subprocess.CalledProcessError as cpe:
        raise HTTPException(status_code=500, detail=f"Docker command failed: {cpe.stderr}")
    return {"password": parsed.get("password", "No password found")}


@app.post("/chirpstack/create-api-key/{name}", dependencies=[Depends(require_internal_token)])
async def chirpstack_create_api_key(name: str = Path(..., min_length=1)):
    if not name.strip() or not SAFE_NAME_PATTERN.match(name):
        raise HTTPException(status_code=400, detail="Invalid or missing 'name' parameter")

    cmd = [
        "docker", "exec", config.CONTAINER_CHIRPSTACK,
        "chirpstack", "--config", "/etc/chirpstack",
        "create-api-key", "--name", name,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as cpe:
        raise HTTPException(status_code=500, detail=f"Failed to create API key: {cpe.stderr.strip()}")

    match = re.search(r"token: (\S+)", result.stdout.strip())
    return {"api_key": match.group(1) if match else "No API key found"}


@app.get("/vault/root-token", dependencies=[Depends(require_internal_token)])
async def vault_root_token():
    cmd = ["docker", "exec", config.CONTAINER_VAULT, "cat", config.VAULT_ROOT_PATH]
    try:
        output = subprocess.check_output(cmd, text=True).strip()
        parsed = json.loads(output)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Failed to parse JSON from Vault response.")
    except subprocess.CalledProcessError as cpe:
        raise HTTPException(status_code=500, detail=f"Docker command failed: {cpe}")

    root_token = parsed.get("root_token")
    if not root_token:
        raise HTTPException(status_code=404, detail="Root token not found in the JSON file.")
    return {"root_token": root_token}

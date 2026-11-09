"""
Container entrypoint for `iot-worker` (see CONTAINERIZATION.md container #2).

Runs as a small FastAPI app (like backup-worker), not a bare blocking script:
api_downlink.py used to reach directly into event_fetcher_parse.key_manager (an
in-memory KeyRotationManager) and call User_token.* functions directly — that
only worked because api and these background loops shared one process. Now
that iot-worker is its own container, api_downlink.py calls the HTTP endpoints
below instead (X-Internal-Token, same pattern as docker-ops-sidecar/backup-worker).

On startup: initializes the KeyRotationManager, then starts the device
scheduler and MQTT event listener as daemon threads — both block forever
on their own.
"""

import logging
import threading

import grpc
from fastapi import Depends, FastAPI, Header, HTTPException, status

import config
from iot_worker import event_fetcher_parse as efp
from iot_worker import User_token
from iot_worker.scheduler import start_scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="iot-worker")


def require_internal_token(x_internal_token: str = Header(default="")):
    if not config.IOT_WORKER_SHARED_SECRET or x_internal_token != config.IOT_WORKER_SHARED_SECRET:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")


def _require_key_manager():
    if not efp.key_manager:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="KeyRotationManager not initialized")


def _require_sent(sent):
    if not sent:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Downlink not sent: no session key for this device yet (or enqueue failed)")


@app.on_event("startup")
def _startup():
    channel = grpc.insecure_channel(config.CHIRPSTACK_HOST)
    efp.initialize_key_rotation(channel, config.AUTH_METADATA)

    threading.Thread(target=start_scheduler, daemon=True).start()
    threading.Thread(target=efp.start_mqtt_client, daemon=True).start()
    logger.info("iot-worker running; scheduler + MQTT listener + key rotation active.")


@app.post("/key-rotation/rotate", dependencies=[Depends(require_internal_token)])
def rotate_keys():
    _require_key_manager()
    efp.key_manager.rotate_keys()
    return {"status": "success"}


@app.post("/devices/{dev_euid}/update-frequency", dependencies=[Depends(require_internal_token)])
def update_frequency(dev_euid: str, update_frequency: int):
    _require_key_manager()
    _require_sent(efp.key_manager.send_update_frequency(dev_euid, update_frequency))
    return {"status": "success"}


@app.post("/devices/{dev_euid}/reboot", dependencies=[Depends(require_internal_token)])
def reboot(dev_euid: str):
    _require_key_manager()
    _require_sent(efp.key_manager.send_reboot_command(dev_euid))
    return {"status": "success"}


@app.post("/devices/{dev_euid}/status", dependencies=[Depends(require_internal_token)])
def device_status(dev_euid: str):
    _require_key_manager()
    _require_sent(efp.key_manager.send_device_status(dev_euid))
    return {"status": "success"}


@app.post("/devices/{dev_euid}/log-level", dependencies=[Depends(require_internal_token)])
def log_level(dev_euid: str, level: int):
    _require_key_manager()
    _require_sent(efp.key_manager.set_log_level(dev_euid, level))
    return {"status": "success"}


@app.post("/devices/{dev_euid}/time-sync", dependencies=[Depends(require_internal_token)])
def time_sync(dev_euid: str):
    _require_key_manager()
    _require_sent(efp.key_manager.send_time_sync(dev_euid))
    return {"status": "success"}


@app.post("/devices/{dev_euid}/reset-factory", dependencies=[Depends(require_internal_token)])
def reset_factory(dev_euid: str):
    _require_key_manager()
    _require_sent(efp.key_manager.send_reset_factory(dev_euid))
    return {"status": "success"}


@app.post("/users/update-list", dependencies=[Depends(require_internal_token)])
def update_user_list():
    User_token.update_user_list()
    return {"status": "success"}


@app.post("/users/rotate-jwt", dependencies=[Depends(require_internal_token)])
def rotate_jwt():
    User_token.Jwt_rotaion_all()
    return {"status": "success"}

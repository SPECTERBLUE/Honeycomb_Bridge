# Honeycomb Bridge

## 📌 Overview

Honeycomb Bridge is the integration layer that sits between the Honeycomb IoT
stack (**ChirpStack**, **EdgeX**, **Magistrala**) and the
Honeycomb frontend. It exposes a single FastAPI surface (`api_downlink.py`)
for auth/MFA, device commands, notifications, TimescaleDB backup/restore, and
predictive-ML routes, backed by a set of independently deployable worker
containers.

What used to be one process (`main.py` running the API plus several
background threads) is now split across **9 containers** — see
[Architecture](#-architecture) below and [CONTAINERIZATION.md](CONTAINERIZATION.md)
for the full rationale behind the split.

### **🚀 Key Features**

- **Auth & MFA**: user login, TOTP-based MFA, captcha, forgot-password, login-alert emails (`auth/`, `captcha_utils.py`, `forgot_password.py`, `SMTP_init.py`).
- **IoT Device Management**: ChirpStack device/application/tenant sync, MQTT event decoding, downlink commands, key rotation, EdgeX user/JWT management (`iot_worker/`).
- **Notifications**: polls EdgeX for notifications, stores them in Postgres, exposes a NEW→CLOSED workflow API (`Notifications/`).
- **TimescaleDB Backup/Restore**: incremental sync from the Magistrala production DB to TimescaleDB, encrypted NAS export/import, scheduled jobs, sync history (`Timescale_db/`).
- **Predictive ML**: telemetry-based training dataset generation and model training/inference for sensor data (`Predictive_ML/`).
- **Docker Ops Sidecar**: the only container with access to the Docker socket; brokers `docker exec` calls into ChirpStack/EdgeX containers on `api`'s behalf (`docker-ops-sidecar/`).

---

## 📂 Project Structure

```
Honeycomb_Bridge/
├── api_downlink.py            # Main FastAPI app (container: api) — auth, devices, notifications,
│                               #   backup/restore, predictive_ML routes; port 4567
├── config.py                  # Shared configuration / env var loading
├── captcha_utils.py           # Redis-backed captcha + AES-GCM helpers (login flow)
├── forgot_password.py         # Password reset token generation/verification
├── SMTP_init.py                # Login-alert email sender
├── User_fetcher.py            # Magistrala user lookups
├── export_openapi.py          # Dumps openapi.json from api_downlink.app
├── codec.js / test.js         # ChirpStack device-profile payload decoders (Decode/decodeUplink) —
│                               #   pasted into ChirpStack's codec config, not run by any service here
├── entrypoint.sh               # api container entrypoint (runs auth.init_db, then uvicorn)
├── Dockerfile                 # api container image
├── docker-compose.yml          # Wires all 9 containers together
├── Makefile                    # docker compose wrappers (build/up/down/logs/sh/migrate/test)
├── CONTAINERIZATION.md         # Container split rationale — read this for "why" questions
│
├── auth/                       # Auth service (container: auth-db is Postgres; code runs inside api)
│   ├── models.py               #   User model: email, secret, mfa_secret, login_alert_email
│   ├── database.py             #   SQLAlchemy engine/session (auth-db, port 5435)
│   ├── auth.py                 #   Auth helpers
│   ├── schemas.py               #   Pydantic schemas
│   └── init_db.py              #   Creates tables on startup
│
├── iot_worker/                  # container: iot-worker — FastAPI app on :8092
│   ├── worker.py                #   HTTP API for device commands (internal-token protected)
│   ├── device_manager.py        #   In-memory device list (euid → codec)
│   ├── device_fetcher.py        #   Fetches devices from ChirpStack
│   ├── application_fetcher.py   #   Fetches applications from ChirpStack
│   ├── tenant_fetcher.py        #   Fetches tenants from ChirpStack
│   ├── codec_fetcher.py         #   Retrieves device codecs
│   ├── event_fetcher_parse.py   #   MQTT listener + payload decoder
│   ├── key_rotation.py          #   ECDH key rotation for device ciphering
│   ├── User_token.py            #   EdgeX admin/user JWTs, writes edgex_users.json
│   ├── downlink.py              #   Downlink message sending
│   ├── scheduler.py             #   Periodic device-list refresh
│   └── send_http_request.py / http_integration_fetcher.py
│
├── Notifications/                # container: notifications-worker
│   ├── worker.py                 #   Polling loop (every 5s), no HTTP API
│   ├── edgex_notification_fetcher.py
│   ├── db_notification/
│   │   ├── models.py             #   notifications / notification_actions tables
│   │   └── crud.py
│   └── schema.py
│
├── Timescale_db/                  # container: backup-worker — FastAPI app on :8091
│   ├── worker.py                  #   Runs backup_scheduler + /reload endpoint (internal-token)
│   ├── backup_scheduler.py        #   APScheduler: daily sync + NAS export jobs
│   ├── sync.py                    #   Incremental watermark sync, source → TimescaleDB
│   ├── reverse_sync.py            #   Restore TimescaleDB → source
│   ├── secure_export.py           #   Encrypt + SFTP export to NAS
│   ├── secure_import.py           #   SFTP download + decrypt + restore
│   ├── transfer_utils.py          #   AES-256-GCM, SHA256, paramiko SFTP helpers
│   ├── db_config.py               #   Source (Magistrala) / target (TimescaleDB) connections
│   └── initdb/01_init.sql         #   Schema bootstrap for the timescaledb container
│
├── Predictive_ML/                  # container: ml-service — FastAPI app on :8093
│   ├── worker.py                   #   Training/prediction/GPU-info routes (torch/xgboost/sklearn)
│   ├── ml/
│   │   ├── train_service.py
│   │   ├── prediction.py
│   │   ├── model_store.py / predition_store.py
│   │   └── trainers/
│   ├── fetch_assets_telemetry.py   #   Stays in api — no ML deps needed
│   ├── telemetry_processor.py
│   ├── training_dataset_csv_creation.py
│   └── requirements.txt            #   torch/xgboost/scikit-learn layer on top of the root image
│
├── docker-ops-sidecar/              # container: docker-ops-sidecar — FastAPI app on :8097
│   ├── main.py                      #   docker exec brokering for ChirpStack/EdgeX ops
│   └── config.py
│
├── alembic/                         # Migrations for auth-db (run manually, not containerized)
│   └── versions/
├── tests/                           # pytest suite for iot_worker fetchers/managers
├── old_code/                        # Pre-container single-process implementation (reference only)
└── data/training_datasets/          # Shared volume between api and ml-service
```

---

## 🏗️ Architecture

Nine containers, one shared bridge network (`honeycomb-net`), plus the
external `magistrala-base-net` for reaching ChirpStack/EdgeX/Magistrala:

| # | Container | Port | Source | Role |
|---|---|---|---|---|
| 1 | `api` | 4567 | `api_downlink.py`, `auth/` | Public FastAPI surface — stateless, scalable |
| 2 | `iot-worker` | 8092 | `iot_worker/` | Device polling, MQTT listener, key rotation, EdgeX JWTs |
| 3 | `notifications-worker` | — | `Notifications/` | EdgeX notification polling loop (no HTTP API) |
| 4 | `backup-worker` | 8091 | `Timescale_db/` | Scheduled backup/restore jobs (APScheduler) |
| 5 | `ml-service` | 8093 | `Predictive_ML/` | Model training + inference (torch/xgboost/sklearn) |
| 6 | `docker-ops-sidecar` | 8097 | `docker-ops-sidecar/` | Only container mounting the Docker socket |
| 7 | `auth-db` | 5435 | `postgres:15` | Users, MFA secrets, notifications tables |
| 8 | `timescaledb` | 5436 | `timescale/timescaledb:2.14.2-pg15` | Backup target DB |
| 9 | `redis` | 6389 | `redis:7-alpine` | Captcha + ML metadata |

ChirpStack and EdgeX run as their own separate Compose stacks and are joined
via the external `magistrala-base-net` network — bring one of those stacks up
first so the network exists before `docker compose up` here.

### Why containers talk to each other over HTTP, not in-process

`api_downlink.py` used to import `iot_worker`, `Timescale_db`, and
`docker-ops-sidecar`-equivalent code directly and call functions in-process.
Now that each lives in its own container, `api` calls them over HTTP instead,
authenticated with a shared-secret header (`X-Internal-Token`), one env var
per callee:

- `iot-worker` → `IOT_WORKER_SHARED_SECRET`
- `backup-worker` → `BACKUP_WORKER_SHARED_SECRET`
- `ml-service` → `ML_SERVICE_SHARED_SECRET`
- `docker-ops-sidecar` → its own internal token, same pattern

### Shared state via bind mounts

A few containers still need to share live files rather than call an API,
because the state is JSON on disk, not a DB row:

- `api` ↔ `backup-worker` share `./Timescale_db` (schedule.json, history
  files). `api` calls `backup-worker`'s `POST /reload` after writing/deleting
  a schedule file so the scheduler picks it up immediately.
- `api` ↔ `iot-worker` ↔ `notifications-worker` share `./edgex_users.json`
  (EdgeX admin/user tokens, maintained by `iot_worker/User_token.py`).
- `api` ↔ `ml-service` share `./data` (training CSVs written by `api`, read
  back by `ml-service`'s `/train`).

### Communication protocols in play

Not everything is REST-over-`honeycomb-net`. By protocol:

| Protocol | Where | Purpose |
|---|---|---|
| HTTP + `X-Internal-Token` | `api` → `iot-worker`/`backup-worker`/`ml-service`/`docker-ops-sidecar` | Internal service calls (see shared secrets above) |
| HTTP (external) | `api`/`iot-worker` → Magistrala, EdgeX Vault, EdgeX notifications, MDL Rules Engine | See external dependencies table below |
| gRPC | `iot_worker/*` (`device_fetcher.py`, `tenant_fetcher.py`, `event_fetcher_parse.py`, `downlink.py`, `key_rotation.py`, `codec_fetcher.py`) → ChirpStack `:8088` | Device/application/tenant CRUD, downlink commands, key rotation |
| MQTT | `iot_worker/event_fetcher_parse.py` → ChirpStack MQTT broker `:1883` | Subscribes to `application/+/device/+/event/+` for uplink payload decoding |
| WebSocket | `api_downlink.py` `/downlink/ws/notifications/{status}` | Server push of notification updates to the frontend |
| SMTP | `SMTP_init.py` → `smtp.gmail.com:587` | Login-alert emails, password/MFA reset links (point back at `FRONTEND_URL`) |
| `docker exec` (via socket) | `docker-ops-sidecar` → `chirpstack`, `edgex-security-proxy-setup`, `edgex-security-secretstore-setup` containers | EdgeX user add, ChirpStack API-key creation, reading the Vault root-init token |
| Redis (TCP) | `api`, `ml-service` → `redis:6389` | Captcha state + AES-GCM login encryption (`captcha_utils.py`); ML model/prediction metadata store (`Predictive_ML/ml/model_store.py`, `predition_store.py`) |

### External dependencies (not in this Compose stack)

Reached via env-configured hostnames, never `localhost`, in production:

- **Magistrala** — main gateway/user-service (`BASE_URL`) and its production TimescaleDB (backup source); a separate **users service** (`USERS_SERVICE_URL`) handles password-reset-without-token
- **ChirpStack** — gRPC `:8088` (device/app/tenant management), HTTP REST `:8090`
- **EdgeX Vault** — `:8200` (JWT/OIDC tokens, root-init secret read via sidecar)
- **EdgeX notifications service** — `:59860` (polled by `notifications-worker`)
- **MDL Rules Engine** — `https://edge.dev.mdl/rules-engine` (rule list/detail/update, called from `iot_worker/User_token.py`)
- **Frontend** — `FRONTEND_URL` (`https://honeycomb.dev.mdl/auth`), the target of password/MFA reset links generated by `api`

See [CONTAINERIZATION.md](CONTAINERIZATION.md) for the full container map,
the reasoning behind each split, and the remaining migration TODOs
(secrets out of `config.py`, replacing the sidecar's `docker exec` calls with
real APIs).

---

## 📦 Installation & Setup

### 1️⃣ Prerequisites

- Docker + Docker Compose
- The `magistrala-base-net` network already exists (bring up the
  ChirpStack or EdgeX Compose stack first — both declare it)
- Python 3.10 (only needed for running things outside Docker, e.g. Alembic)

### 2️⃣ Clone the Repository

```sh
git clone https://github.com/your-repo/honeycomb-bridge.git
cd honeycomb-bridge
```

### 3️⃣ Configure environment files

- `.env` — ChirpStack/MQTT/EdgeX hosts, Redis, internal shared-secret tokens
- `auth/.env.docker` — auth-db `DATABASE_URL` and credentials
- `Timescale_db/.env` — `SOURCE_DB_*`, `TARGET_DB_*`, `BACKUP_ENCRYPTION_KEY`

### 4️⃣ Build and start the stack

```sh
make build
make up
make ps        # check container status
make logs SERVICE=api   # tail a specific service, or omit SERVICE for all
```

### 5️⃣ Run database migrations (auth-db, host-side, out of scope for containers)

```sh
make migrate
```

---

## 📋 Running Individual Services (without Docker)

Each worker also runs as a standalone FastAPI/loop process for local
development:

```sh
python3 -m uvicorn api_downlink:app --host 0.0.0.0 --port 4567
python3 -m uvicorn iot_worker.worker:app --host 0.0.0.0 --port 8092
python3 -m uvicorn worker:app --app-dir Timescale_db --host 0.0.0.0 --port 8091
python3 -m uvicorn Predictive_ML.worker:app --host 0.0.0.0 --port 8093
python3 -m Notifications.worker
```

---

## 🔧 Debugging & Logs

```sh
make logs                        # all containers
make logs SERVICE=iot-worker     # one container
make sh SERVICE=api              # shell into a container
```

---

## 🧪 Tests

```sh
make test
# or
pytest -v
```

---

## 📌 Migration Notes

- `old_code/` holds the pre-container, single-process implementation for
  reference — not run in production.
- Alembic migrations (`alembic/versions/`) are intentionally **out of scope**
  for containerization and continue to run manually against the host/auth-db
  via `make migrate` / `make revision`.
- See [CONTAINERIZATION.md](CONTAINERIZATION.md) for the outstanding items:
  moving secrets out of `config.py`, and replacing `docker-ops-sidecar`'s
  `docker exec` calls with real ChirpStack/Vault APIs.

---

## 📝 License

This project is licensed under the **MIT License**.

## 👨‍💻 Contributing

Pull requests are welcome! Open an issue for discussions. See
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

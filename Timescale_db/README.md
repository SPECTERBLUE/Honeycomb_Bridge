# Magistrala Messages — DB Backup & Restore Pipeline

A two-path backup and restore system for the **Production DB (Magistrala Messages)** built on TimescaleDB, with AES-256-GCM encryption and SFTP transfer to any external server or NAS.

---

## Architecture

### Path 1 — Internal Sync (Direct)

Fast, low-latency sync between the two local databases.

```
Production DB (Magistrala :5433)
        │
        ▼
  Batch Extract (10,000 rows)
        │
        ▼
  Internal Sync Service (sync.py)
        │
        ▼
  Direct Insert
        │
        ▼
  Backup DB (TimescaleDB :5436)
        │
        ▼
  Restore Service (reverse_sync.py)
        │
        ▼
  Production DB (Magistrala :5433)
```

### Path 2 — Secure External Transfer

Encrypted, integrity-verified transfer to any remote server or NAS.

```
Production DB (Magistrala :5433)
        │
        ▼
  Batch Extract (10,000 rows)
        │
        ▼
  AES-256-GCM Encryption (per batch)
        │
        ▼
  SHA256 Checksum (per batch)
        │
        ▼
  SFTP Transfer → External Server / NAS
        │
        ├─── Restore to Backup DB ────────────────────────────────────────┐
        │         Verify SHA256 → Decrypt → Insert into TimescaleDB       │
        │                                                                  │
        └─── Restore to Production DB ────────────────────────────────────┘
                  Verify SHA256 → Decrypt → Insert into Magistrala
```

---

## Project Structure

```
timescale-db-new/
├── apis.py                # FastAPI REST API — all 26 endpoints (standalone server)
├── backup_scheduler.py    # Singleton APScheduler — shared by apis.py and main.py
├── sync.py                # Internal sync: Production DB → TimescaleDB
├── reverse_sync.py        # Internal restore: TimescaleDB → Production DB
├── secure_export.py       # Secure export: Production DB → encrypt → SFTP → External Server
├── secure_import.py       # Secure import: External Server → verify → decrypt → DB
├── transfer_utils.py      # Shared: AES-256-GCM, SHA256, SFTP helpers
├── db_config.py           # DB connection config
├── schedule.json          # Auto-created when a schedule is set — persists across restarts
├── nas_config.json        # Auto-created on first export — saves NAS server details (no passwords)
├── nas_schedule.json      # Auto-created when NAS schedule is set — includes SSH credentials
├── backup_history.json    # Auto-created — last 1000 backup run records
├── nas_history.json       # Auto-created — last 1000 NAS export run records
├── .env                   # Environment variables — DB credentials, encryption key, alert email
├── docker-compose.yaml    # TimescaleDB container
└── initdb/
    └── 01_init.sql        # Schema: messages, backup_control, backup_metadata
```

---

## Setup

### 1. Start TimescaleDB

```bash
docker compose up -d
```

TimescaleDB starts on port `5436`. Schema is auto-applied from `initdb/01_init.sql`.

### 2. Install Python dependencies

```bash
pip install fastapi uvicorn psycopg2-binary paramiko cryptography apscheduler
```

### 3. Configure environment variables

Copy `.env` and fill in your values:

```bash
cp .env .env.local   # optional — keep originals clean
```

Edit `.env`:

```env
# Generate encryption key once and store securely:
# python3 -c "import os; print(os.urandom(32).hex())"
BACKUP_ENCRYPTION_KEY=your_64_char_hex_key_here

SOURCE_DB_HOST=localhost
SOURCE_DB_PORT=5433
SOURCE_DB_NAME=magistrala
SOURCE_DB_USER=magistrala
SOURCE_DB_PASSWORD=your_production_db_password

TARGET_DB_HOST=localhost
TARGET_DB_PORT=5436
TARGET_DB_NAME=timeseries_db
TARGET_DB_USER=ts_user
TARGET_DB_PASSWORD=your_backup_db_password

```

Load the env vars before starting:

```bash
export $(grep -v '^#' .env | xargs)
```

Or if using `python-dotenv`:

```bash
pip install python-dotenv
```

```python
from dotenv import load_dotenv
load_dotenv()
```

**Integrated into your main server (`main.py`):**

If the backup module is embedded into your existing FastAPI server, add the following to `main.py` so the backup scheduler starts alongside your other services:

```python
# At the top of main.py — add after your existing imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'timescale-db-new'))
from backup_scheduler import start_backup_scheduler
```

```python
# In the main block — add after starting the device scheduler
logger.info("Starting backup scheduler...")
backup_sched_thread = threading.Thread(target=start_backup_scheduler, daemon=True)
backup_sched_thread.start()
```

The scheduler reads `schedule.json` on startup and restores any previously saved schedule automatically. No extra setup needed after the first `POST /downlink/backup/schedule` call.

---

## Database Config

Defined in `db_config.py`:

| DB | Host | Port | Name | User |
|----|------|------|------|------|
| Production (Magistrala) | localhost | 5433 | magistrala | magistrala |
| Backup (TimescaleDB) | localhost | 5436 | timeseries_db | ts_user |

---

## API Reference

All endpoints are prefixed with `/downlink/guardian`.

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/guardian/health` | Check if Production DB is reachable |
| GET | `/downlink/guardian/backup-db/health` | Check if Backup DB (TimescaleDB) is reachable |

### Internal Sync

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/guardian/backup` | Incremental sync: Production DB → TimescaleDB |
| POST | `/downlink/guardian/restore` | Full restore: TimescaleDB → Production DB |
| POST | `/downlink/guardian/restore/time?hours=N` | Restore last N hours of data |
| POST | `/downlink/guardian/restore/range` | Restore rows within a specific date range |

### Backup Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/guardian/backup/status` | Check if backup is enabled |
| POST | `/downlink/guardian/backup/enable` | Enable backup |
| POST | `/downlink/guardian/backup/disable` | Disable backup |
| POST | `/downlink/guardian/backup/reset-watermark` | Reset sync watermark (use after backup DB data loss) |
| POST | `/downlink/guardian/backup/schedule` | Set a recurring daily automatic backup |
| GET | `/downlink/guardian/backup/schedule` | Get current schedule |
| DELETE | `/downlink/guardian/backup/schedule` | Remove the scheduled backup |

### Stats

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/guardian/backup/sync-status` | Compare Production vs Backup DB counts, show diff and next schedule |
| GET | `/downlink/guardian/backup/last` | Last sync watermark timestamp |
| GET | `/downlink/guardian/backup/history?limit=20` | Backup run records, newest first (default 20, max 1000) |
| GET | `/downlink/guardian/nas/history?limit=20` | NAS export run records, newest first (default 20, max 1000) |

### Secure External Transfer

All three endpoints accept the same JSON body:

```json
{
  "host": "192.168.1.15",
  "port": 22,
  "username": "your-ssh-user",
  "password": "your-ssh-password",
  "remote_path": "/home/your-ssh-user/backup-folder"
}
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/guardian/secure-export` | Export Production DB → encrypt → SHA256 → SFTP to any server |
| POST | `/downlink/guardian/secure-export/list` | List all export folders on NAS with date and row counts |
| POST | `/downlink/guardian/secure-export/preview` | Decrypt and preview rows from a batch file on NAS — no DB write |
| POST | `/downlink/guardian/secure-import/backup-db` | Import from server → verify → decrypt → TimescaleDB |
| POST | `/downlink/guardian/secure-import/production-db` | Import from server → verify → decrypt → Production DB |
| GET | `/downlink/guardian/nas-config` | List all previously used NAS servers (for form pre-fill) |

### NAS Backup Schedule

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/guardian/nas-backup/schedule` | Set a recurring daily NAS export |
| GET | `/downlink/guardian/nas-backup/schedule` | Get current NAS schedule |
| DELETE | `/downlink/guardian/nas-backup/schedule` | Remove the NAS schedule |

**Set NAS schedule:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/nas-backup/schedule" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "02:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/backups"
  }'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "02:00",
  "timezone": "Asia/Kolkata",
  "target": "honeycomb@192.168.1.15:22/home/honeycomb/backups",
  "next_run": "2026-06-14T02:00:00+05:30",
  "note": "NAS export runs daily at the specified time. Persisted — survives API restarts."
}
```

**Get NAS schedule:**
```bash
curl "http://localhost:4567/downlink/guardian/nas-backup/schedule"
```

Response:
```json
{
  "scheduled": true,
  "schedule": {
    "time": "02:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "remote_path": "/home/honeycomb/backups"
  },
  "next_run": "2026-06-14T02:00:00+05:30"
}
```

**Remove NAS schedule:**
```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/nas-backup/schedule"
```

Response:
```json
{"status": "NAS schedule removed"}
```

**List saved NAS servers (pre-fill form):**
```bash
curl "http://localhost:4567/downlink/guardian/nas-config"
```

Response:
```json
{
  "total": 2,
  "servers": [
    {
      "host": "192.168.1.15",
      "port": 22,
      "username": "honeycomb",
      "remote_path": "/home/honeycomb/backups",
      "last_used": "2026-06-14T21:00:00+00:00"
    },
    {
      "host": "192.168.1.15",
      "port": 22,
      "username": "honeycomb",
      "remote_path": "/mnt/nas/data",
      "last_used": "2026-06-10T09:00:00+00:00"
    }
  ]
}
```

> Sorted newest first. Same host with a different path is a separate entry. Passwords are never stored.

**Secure export — tested curl:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-export" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup"
  }'
```

Response:
```json
{
  "status": "SUCCESS",
  "total_rows": 95390,
  "total_batches": 10,
  "duration_seconds": 1.67,
  "export_path": "/home/honeycomb/test-nas-backup/export_20260612_093045"
}
```

> Each export creates a timestamped subfolder so multiple exports never overwrite each other.
> Use the returned `export_path` as `remote_path` in import and preview calls.
> If `remote_path` does not exist on the NAS, it is created automatically.
> Data is gzip compressed before encryption — expect ~2–3 MB per batch instead of ~12 MB.
> NAS server details (host, port, username, path) are saved automatically to `nas_config.json` on every successful export — same host with a different path is stored as a separate entry.

**List all exports on NAS:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-export/list" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup"
  }'
```

Response:
```json
{
  "total": 3,
  "exports": [
    {
      "folder": "export_20260612_093045",
      "export_path": "/home/honeycomb/test-nas-backup/export_20260612_093045",
      "exported_at": "2026-06-12T09:30:45+00:00",
      "total_rows": 95390,
      "total_batches": 10
    },
    {
      "folder": "export_20260611_120000",
      "export_path": "/home/honeycomb/test-nas-backup/export_20260611_120000",
      "exported_at": "2026-06-11T12:00:00+00:00",
      "total_rows": 90000,
      "total_batches": 9
    }
  ]
}
```

Returns newest first. Copy `export_path` from any entry and pass it as `remote_path` to import or preview.

**Secure import into Backup DB — tested curl:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup"
  }'
```

Response:
```json
{
  "status": "SUCCESS",
  "target": "backup",
  "batches_verified": 10,
  "rows_inserted": 95390,
  "duration_seconds": 38.7
}
```

**Secure import into Production DB — tested curl:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/production-db" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup"
  }'
```

Response:
```json
{
  "status": "SUCCESS",
  "target": "production",
  "batches_verified": 10,
  "rows_inserted": 95390,
  "duration_seconds": 41.2
}
```

> **Note:** Use the local network IP (e.g. `192.168.1.x`) not the public IP. Public IPs may be blocked by firewall on port 22.

**Preview batch data on NAS (no DB write) — tested curl:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-export/preview" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup",
    "batch": 0,
    "rows": 10
  }'
```

Response:
```json
{
  "batch": 0,
  "file": "batch_000000.enc",
  "total_rows_in_batch": 10000,
  "rows_returned": 10,
  "checksum_verified": true,
  "columns": ["time", "channel", "subtopic", "publisher", "protocol", "name", "unit", "value", "string_value", "bool_value", "data_value", "sum", "update_time"],
  "data": [
    { "time": "1700000000", "channel": "531a610d-...", "name": "temp", "value": "22.5", ... },
    ...
  ]
}
```

Parameters:
- `batch` — which batch to inspect (0-based, check `manifest.json` for total count)
- `rows` — how many rows to return (1–1000)

Decrypts in memory only — nothing is written to any database.

---

## Date-Range Restore

Restore only the rows between two specific dates from Backup DB → Production DB. Useful when you need to recover data for a specific day or window without overwriting everything.

```bash
curl -X POST "http://localhost:4567/downlink/guardian/restore/range" \
  -H "Content-Type: application/json" \
  -d '{"start": "2026-06-06T00:00:00", "end": "2026-06-07T23:59:59"}'
```

Response:
```json
{
  "status": "SUCCESS",
  "start": "2026-06-06T00:00:00+00:00",
  "end": "2026-06-07T23:59:59+00:00",
  "rows_found": 12400,
  "rows_inserted": 12400
}
```

- `start` and `end` are UTC ISO datetime strings
- Queries the Backup DB's `update_time` column (which records when each row was backed up)
- Uses `ON CONFLICT DO NOTHING` — existing rows in Production DB are not overwritten

---

## Scheduled Backup

Set a recurring daily backup that runs automatically without any manual trigger. The schedule is saved to `schedule.json` and restored when the API restarts.

### Set schedule

Requires a Bearer token — the authenticated user's `login_alert_email` is used for failure alerts.

```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"time": "00:00", "timezone": "UTC"}'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "00:00",
  "timezone": "UTC",
  "next_run": "2026-06-13T00:00:00+00:00",
  "note": "Backup runs daily at the specified time. Persisted — survives API restarts."
}
```

With Indian timezone:
```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"time": "00:00", "timezone": "Asia/Kolkata"}'
```

### Get current schedule

```bash
curl "http://localhost:4567/downlink/guardian/backup/schedule"
```

Response (schedule active):
```json
{
  "scheduled": true,
  "schedule": {"time": "00:00", "timezone": "UTC"},
  "next_run": "2026-06-13T00:00:00+00:00"
}
```

Response (no schedule set):
```json
{"scheduled": false, "schedule": null, "next_run": null}
```

### Remove schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/backup/schedule"
```

Response:
```json
{"status": "Schedule removed"}
```

**Notes:**
- Requires `apscheduler` installed: `pip install apscheduler`
- Schedule persists across API restarts via `schedule.json`
- The scheduled job runs the same incremental sync as `POST /downlink/backup`
- Use any IANA timezone name (e.g. `UTC`, `Asia/Kolkata`, `America/New_York`)
- Max timeout per sync run: **1 hour** (handles up to ~10 lakh rows; typical run ~15 min)

### Failure Alerts

When the scheduled backup fails, an email alert is sent automatically to the user who set the schedule. The recipient is determined from the Bearer token used when calling `POST /downlink/backup/schedule` — their `login_alert_email` from the users table is used. No extra configuration needed.

Alert is triggered when:
- Production DB or Backup DB is unreachable
- Sync script crashes or throws an exception
- Sync takes longer than 1 hour (timeout)

---

## CLI Usage

The sync and secure transfer scripts can also be run directly without the API.

### Internal sync

```bash
# Production DB → TimescaleDB
python sync.py

# TimescaleDB → Production DB (full restore)
python reverse_sync.py

# TimescaleDB → Production DB (last 24 hours)
python reverse_sync.py 24

# TimescaleDB → Production DB (last 500 records)
python reverse_sync.py --limit 500
```

### Secure external transfer

```bash
# Export to external server
export BACKUP_ENCRYPTION_KEY=<key>
python secure_export.py <host> <port> <username> <password> <remote_path>

# Import from external server into TimescaleDB
python secure_import.py <host> <port> <username> <password> <remote_path> backup

# Import from external server into Production DB
python secure_import.py <host> <port> <username> <password> <remote_path> production
```

---

## What Gets Written to the Remote Server

Each export creates a timestamped subfolder under `remote_path` so multiple exports never overwrite each other:

```
remote_path/
├── export_20260610_120000/        ← Day 1
│   ├── manifest.json              # Row counts, checksums, export timestamp
│   ├── batch_000000.enc           # AES-256-GCM encrypted batch (rows 0–9999)
│   ├── batch_000000.sha256        # SHA256 of the encrypted file
│   ├── batch_000001.enc
│   ├── batch_000001.sha256
│   └── ...
├── export_20260611_120000/        ← Day 2 (never overwrites Day 1)
│   └── ...
└── export_20260612_093045/        ← Day 3
    └── ...
```

### Encryption format per batch file

```
[12 bytes — random nonce] [N bytes — ciphertext + 16-byte GCM tag]
```

The SHA256 checksum is computed over the full encrypted file (nonce + ciphertext + tag) so any corruption or tampering during transfer is caught before decryption is attempted.

---

## Security

| Concern | Approach |
|---------|----------|
| Data confidentiality | AES-256-GCM per batch — each batch has a unique random nonce |
| Transfer integrity | SHA256 checksum verified before decryption on every import |
| Authenticated encryption | GCM tag detects ciphertext tampering without a separate HMAC |
| Transport security | SFTP over SSH — no plaintext data ever leaves the host |
| Key management | Key stored only in `BACKUP_ENCRYPTION_KEY` env var, never written to disk or logs |

### What travels over the network

**Export (Production DB → NAS)**
- Only AES-256-GCM encrypted bytes are sent — plain CSV never leaves the machine

**Import / Preview (NAS → Your Machine)**
- Only AES-256-GCM encrypted bytes are received — decryption happens in memory after download

**Transport layer (SFTP over SSH)**
- SSH tunnel encrypts the already-encrypted data a second time — double encrypted in transit

| Layer | What it protects |
|-------|-----------------|
| AES-256-GCM | Data at rest on NAS — files are unreadable without the key even if someone gets physical access |
| SSH/SFTP tunnel | Data in transit — unreadable even if someone intercepts the network traffic |

> Plain data exists only in RAM during the encrypt/decrypt step — it never touches the network or disk unencrypted.

---

## Schema

Defined in `initdb/01_init.sql`.

### `messages` (TimescaleDB hypertable)

| Column | Type | Notes |
|--------|------|-------|
| time | BIGINT | Epoch timestamp — partition key |
| channel | UUID | |
| subtopic | VARCHAR | |
| publisher | UUID | |
| protocol | TEXT | |
| name | VARCHAR | |
| unit | TEXT | |
| value | DOUBLE PRECISION | |
| string_value | TEXT | |
| bool_value | BOOLEAN | |
| data_value | BYTEA | |
| sum | DOUBLE PRECISION | |
| update_time | TIMESTAMP | When row was written into backup DB |

Unique index on `(time, channel, name)`.

### `backup_control`

Single-row flag table. Set `enabled = FALSE` to pause all sync jobs without stopping the service.

### `backup_metadata`

Stores `last_synced_time` and `last_message_time` (watermark) used by the incremental sync to avoid re-processing already-synced rows.

---

## Watermark Reset (Disaster Recovery)

The incremental sync tracks a watermark (`last_message_time`) so each run only fetches rows newer than the last sync. If the backup DB crashes and loses data, the watermark still points to the old position — the next sync would fetch 0 rows and miss all the lost data.

Use this endpoint to reset the watermark before re-running the sync:

**Full re-sync from beginning:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup/reset-watermark"
```

Response:
```json
{
  "status": "Watermark reset",
  "last_message_time": "1970-01-01T00:00:00+00:00",
  "note": "Next /downlink/backup run will re-sync all rows after this time"
}
```

**Partial re-sync from a specific date:**
```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup/reset-watermark?from_time=2026-06-01T00:00:00"
```

Then trigger the sync:
```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup"
```

> This is a rare operation — only needed after backup DB data loss or migration to a new backup DB. In normal operation the watermark manages itself automatically.

---

## Known Behaviours

| Behaviour | Detail |
|-----------|--------|
| Float epoch strings | Source DB stores `update_time` as BIGINT but psycopg2 may return `0.0` — handled with `int(float(...))` |
| NULL subtopic | Production DB requires `subtopic NOT NULL` — rows with NULL subtopic default to `''` on import |
| SSH key scanning disabled | paramiko uses password-only auth (`look_for_keys=False`, `allow_agent=False`) to avoid handshake delays |
| Sync timeout | All sync and restore operations have a 1-hour max timeout — enough for ~10 lakh rows (typical run ~15 min) |
| Scheduled backup alerts | Failure email goes to the user who set the schedule (resolved from Bearer token at schedule time via `login_alert_email`) — no separate config needed |
| Timezone-aware restore | Date-range restore handles both UTC and timezone-aware datetime strings correctly via `astimezone()` |
| DB credentials | All DB credentials read from environment variables — set in `.env`, never hardcoded |

---

## Decrypt a Batch File Manually

To inspect the contents of any `.enc` file from the remote server:

```bash
# Copy batch file locally
scp user@192.168.1.15:/home/user/backup-folder/batch_000000.enc /tmp/

# Set encryption key
export BACKUP_ENCRYPTION_KEY=your_64_char_hex_key

# Decrypt and preview
cd /path/to/project
python3 - << 'EOF'
from transfer_utils import decrypt, load_key

key = load_key()
with open('/tmp/batch_000000.enc', 'rb') as f:
    encrypted = f.read()

plaintext = decrypt(encrypted, key)
lines = plaintext.decode('utf-8').splitlines()

print(f'Total rows: {len(lines) - 1}')
print(lines[0])           # header
for line in lines[1:6]:   # first 5 rows
    print(line)
EOF
```

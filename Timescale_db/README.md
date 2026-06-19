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
Timescale_db/
├── backup_scheduler.py             # Singleton APScheduler — all 5 schedule types
├── sync.py                         # Internal sync: Production DB → TimescaleDB
├── reverse_sync.py                 # Internal restore: TimescaleDB → Production DB
├── secure_export.py                # Secure export: Production DB → encrypt → SFTP
├── secure_import.py                # Secure import: SFTP → verify → decrypt → DB
├── transfer_utils.py               # Shared: AES-256-GCM, SHA256, SFTP helpers
├── db_config.py                    # DB connection config
├── schedule.json                   # Auto-created — backup schedule
├── nas_schedule.json               # Auto-created — NAS export schedule
├── restore_schedule.json           # Auto-created — restore schedule
├── import_backup_schedule.json     # Auto-created — secure-import backup-db schedule
├── import_production_schedule.json # Auto-created — secure-import production-db schedule
├── nas_config.json                 # Auto-created — NAS server list (no passwords)
├── backup_history.json             # Auto-created — last 1000 backup run records
├── nas_history.json                # Auto-created — last 1000 NAS export run records
├── import_backup_history.json      # Auto-created — last 1000 import-backup run records
├── import_production_history.json  # Auto-created — last 1000 import-production run records
├── .env                            # DB credentials, encryption key, alert email
├── docker-compose.yaml             # TimescaleDB container
└── initdb/
    └── 01_init.sql                 # Schema: messages, backup_control, backup_metadata
```

All 5 `*.json` schedule files are restored automatically on API startup — no manual intervention needed after a restart.

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

Edit `.env`:

```env
# Generate once: python3 -c "import os; print(os.urandom(32).hex())"
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

### 4. Integrate into main server

Add to `main.py`:

```python
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Timescale_db'))
from backup_scheduler import start_backup_scheduler
```

```python
logger.info("Starting backup scheduler...")
backup_sched_thread = threading.Thread(target=start_backup_scheduler, daemon=True)
backup_sched_thread.start()
```

---

## Database Config

| DB | Host | Port | Name | User |
|----|------|------|------|------|
| Production (Magistrala) | localhost | 5433 | magistrala | magistrala |
| Backup (TimescaleDB) | localhost | 5436 | timeseries_db | ts_user |

---

## API Reference

All 32 endpoints are prefixed with `/downlink/guardian`.

### Full Endpoint List

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 1 | GET | `/downlink/guardian/health` | Production DB reachability check |
| 2 | GET | `/downlink/guardian/backup-db/health` | Backup DB (TimescaleDB) reachability check |
| 3 | POST | `/downlink/guardian/backup` | Manual incremental sync — **max 50,000 rows** |
| 4 | GET | `/downlink/guardian/backup/status` | Check if backup is enabled |
| 5 | POST | `/downlink/guardian/backup/enable` | Enable backup |
| 6 | POST | `/downlink/guardian/backup/disable` | Disable backup |
| 7 | POST | `/downlink/guardian/backup/reset-watermark` | Reset sync watermark |
| 8 | GET | `/downlink/guardian/backup/sync-status` | Compare row counts, show diff and next schedule |
| 9 | POST | `/downlink/guardian/backup/schedule` | Set daily backup schedule (5 modes, 409 conflict) |
| 10 | GET | `/downlink/guardian/backup/schedule` | Get current backup schedule |
| 11 | DELETE | `/downlink/guardian/backup/schedule` | Remove backup schedule |
| 12 | GET | `/downlink/guardian/backup/history` | Backup run history |
| 13 | POST | `/downlink/guardian/nas-backup/schedule` | Set daily NAS export schedule (4 modes, 409 conflict) |
| 14 | GET | `/downlink/guardian/nas-backup/schedule` | Get current NAS schedule |
| 15 | DELETE | `/downlink/guardian/nas-backup/schedule` | Remove NAS schedule |
| 16 | GET | `/downlink/guardian/nas/history` | NAS export run history |
| 17 | GET | `/downlink/guardian/nas-config` | List previously used NAS servers |
| 18 | POST | `/downlink/guardian/restore/schedule` | Set daily restore schedule (4 modes, 409 conflict) |
| 19 | GET | `/downlink/guardian/restore/schedule` | Get current restore schedule |
| 20 | DELETE | `/downlink/guardian/restore/schedule` | Remove restore schedule |
| 21 | GET | `/downlink/guardian/restore/history` | Restore run history |
| 22 | POST | `/downlink/guardian/secure-export` | Export to NAS — **max 200,000 rows** |
| 23 | POST | `/downlink/guardian/secure-export/list` | List all export folders on NAS |
| 24 | POST | `/downlink/guardian/secure-export/preview` | Preview rows from a NAS batch (no DB write) |
| 25 | POST | `/downlink/guardian/secure-import/backup-db` | Import NAS → TimescaleDB — **max 50,000 rows** |
| 26 | POST | `/downlink/guardian/secure-import/production-db` | Import NAS → Production DB — **max 50,000 rows** |
| 27 | POST | `/downlink/guardian/secure-import/backup-db/schedule` | Set daily import-to-backup-db schedule (4 modes, 409 conflict) |
| 28 | GET | `/downlink/guardian/secure-import/backup-db/schedule` | Get current import-backup-db schedule |
| 29 | DELETE | `/downlink/guardian/secure-import/backup-db/schedule` | Remove import-backup-db schedule |
| 30 | POST | `/downlink/guardian/secure-import/production-db/schedule` | Set daily import-to-production-db schedule (4 modes, 409 conflict) |
| 31 | GET | `/downlink/guardian/secure-import/production-db/schedule` | Get current import-production-db schedule |
| 32 | DELETE | `/downlink/guardian/secure-import/production-db/schedule` | Remove import-production-db schedule |

---

## 1–2. Health

```bash
curl "http://localhost:4567/downlink/guardian/health"
curl "http://localhost:4567/downlink/guardian/backup-db/health"
```

Response:
```json
{"status": "ok", "db": "production"}
{"status": "ok", "db": "backup"}
```

---

## 3–8. Manual Backup & Control

### 3. POST /downlink/guardian/backup

Manual incremental sync: Production DB → TimescaleDB. Hard-capped at **50,000 rows** to prevent frontend timeouts. Checks `backup_control.enabled` before running.

```bash
curl -X POST "http://localhost:4567/downlink/guardian/backup"
```

Response:
```json
{
  "status": "SUCCESS",
  "rows_fetched": 50000,
  "rows_upserted": 50000,
  "limit": 50000,
  "duration_seconds": 4.21,
  "note": "Manual trigger capped at 50000 rows. Use the scheduled backup for full incremental sync."
}
```

> To sync beyond 50,000 rows at once, use `POST /downlink/guardian/backup/schedule` with mode `incremental` or `full` — scheduled jobs have no row cap.

### 4–6. Backup Control

```bash
curl "http://localhost:4567/downlink/guardian/backup/status"
curl -X POST "http://localhost:4567/downlink/guardian/backup/enable"
curl -X POST "http://localhost:4567/downlink/guardian/backup/disable"
```

`/status` response:
```json
{"enabled": true}
```

### 7. POST /downlink/guardian/backup/reset-watermark

Resets the incremental sync watermark. Use after backup DB data loss so the next sync re-fetches from a specific point.

```bash
# Reset to beginning (full re-sync)
curl -X POST "http://localhost:4567/downlink/guardian/backup/reset-watermark"

# Reset to a specific date
curl -X POST "http://localhost:4567/downlink/guardian/backup/reset-watermark?from_time=2026-06-01T00:00:00"
```

Response:
```json
{
  "status": "Watermark reset",
  "last_message_time": "1970-01-01T00:00:00+00:00",
  "note": "Next /downlink/backup run will re-sync all rows after this time"
}
```

### 8. GET /downlink/guardian/backup/sync-status

Compares Production DB vs Backup DB row counts, shows lag, and reports next scheduled run.

```bash
curl "http://localhost:4567/downlink/guardian/backup/sync-status"
```

Response:
```json
{
  "production_count": 1250000,
  "backup_count": 1248500,
  "diff": 1500,
  "last_synced": "2026-06-18T02:00:00+00:00",
  "next_run": "2026-06-19T02:00:00+00:00"
}
```

---

## 9–12. Backup Schedule

Daily automated sync from Production DB → TimescaleDB. Persisted to `schedule.json`.

### Modes

| Mode | What it does | Required fields |
|------|-------------|-----------------|
| `incremental` | (default) Fetches only rows newer than the last watermark | — |
| `full` | Resets watermark to NULL then runs a complete sync | — |
| `limit` | Fetches the N most-recent rows by `update_time` | `limit` |
| `hours` | Fetches rows with `update_time` in the last N hours | `hours` |
| `range` | Fetches rows with `update_time` between two datetimes | `start`, `end` |

### 9. POST /downlink/guardian/backup/schedule

Requires Bearer token. Returns **409** if a schedule already exists — DELETE it first.

```bash
# Incremental (default — recommended for daily use)
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "02:00", "timezone": "Asia/Kolkata", "mode": "incremental"}'

# Full sync nightly
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "01:00", "timezone": "Asia/Kolkata", "mode": "full"}'

# Last 10,000 rows daily
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "03:00", "timezone": "Asia/Kolkata", "mode": "limit", "limit": 10000}'

# Last 24 hours daily
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "03:00", "timezone": "Asia/Kolkata", "mode": "hours", "hours": 24}'

# Fixed date range
curl -X POST "http://localhost:4567/downlink/guardian/backup/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "04:00", "timezone": "UTC", "mode": "range", "start": "2026-06-01T00:00:00", "end": "2026-06-18T23:59:59"}'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "02:00",
  "timezone": "Asia/Kolkata",
  "mode": "incremental",
  "next_run": "2026-06-19T02:00:00+05:30",
  "note": "Backup runs daily at the specified time. Persisted — survives API restarts."
}
```

409 response (schedule already exists):
```json
{"detail": "A backup schedule already exists. DELETE /downlink/guardian/backup/schedule first."}
```

### 10. GET /downlink/guardian/backup/schedule

```bash
curl "http://localhost:4567/downlink/guardian/backup/schedule"
```

Response:
```json
{
  "scheduled": true,
  "schedule": {"time": "02:00", "timezone": "Asia/Kolkata", "mode": "incremental"},
  "next_run": "2026-06-19T02:00:00+05:30"
}
```

No schedule set:
```json
{"scheduled": false, "schedule": null, "next_run": null}
```

### 11. DELETE /downlink/guardian/backup/schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/backup/schedule"
```

Response:
```json
{"status": "Schedule removed"}
```

### 12. GET /downlink/guardian/backup/history

```bash
curl "http://localhost:4567/downlink/guardian/backup/history?limit=20"
```

Response:
```json
{
  "total": 2,
  "history": [
    {"ran_at": "2026-06-18T02:00:01+00:00", "status": "SUCCESS", "rows_synced": 1500, "duration_seconds": 0.82},
    {"ran_at": "2026-06-17T02:00:01+00:00", "status": "SUCCESS", "rows_synced": 2100, "duration_seconds": 1.03}
  ]
}
```

Default 20, max 1000.

---

## 13–17. NAS Backup Schedule & Config

Daily automated export from Production DB → encrypted → SFTP to remote NAS. Persisted to `nas_schedule.json`.

### Modes

| Mode | What it does | Required fields |
|------|-------------|-----------------|
| `full` | (default) Exports all rows from Production DB | — |
| `limit` | Exports the N most-recent rows | `limit` |
| `hours` | Exports rows from the last N hours | `hours` |
| `range` | Exports rows between two datetimes | `start`, `end` |

### 13. POST /downlink/guardian/nas-backup/schedule

Returns **409** if a schedule already exists — DELETE it first.

```bash
# Full export nightly
curl -X POST "http://localhost:4567/downlink/guardian/nas-backup/schedule" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "02:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "full"
  }'

# Last 24 hours nightly
curl -X POST "http://localhost:4567/downlink/guardian/nas-backup/schedule" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "02:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "hours", "hours": 24
  }'

# Last 50,000 rows nightly
curl -X POST "http://localhost:4567/downlink/guardian/nas-backup/schedule" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "02:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "limit", "limit": 50000
  }'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "02:00",
  "timezone": "Asia/Kolkata",
  "mode": "full",
  "target": "honeycomb@192.168.1.15:22/home/honeycomb/backups",
  "next_run": "2026-06-19T02:00:00+05:30",
  "note": "NAS export runs daily at the specified time. Persisted — survives API restarts."
}
```

409 response:
```json
{"detail": "A NAS schedule already exists. DELETE /downlink/guardian/nas-backup/schedule first."}
```

### 14. GET /downlink/guardian/nas-backup/schedule

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
    "remote_path": "/home/honeycomb/backups",
    "mode": "full"
  },
  "next_run": "2026-06-19T02:00:00+05:30"
}
```

### 15. DELETE /downlink/guardian/nas-backup/schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/nas-backup/schedule"
```

Response:
```json
{"status": "NAS schedule removed"}
```

### 16. GET /downlink/guardian/nas/history

```bash
curl "http://localhost:4567/downlink/guardian/nas/history?limit=20"
```

Response:
```json
{
  "total": 1,
  "history": [
    {
      "ran_at": "2026-06-18T02:00:05+00:00",
      "status": "SUCCESS",
      "total_rows": 95390,
      "total_batches": 10,
      "mode": "full",
      "duration_seconds": 1.67
    }
  ]
}
```

### 17. GET /downlink/guardian/nas-config

Lists all previously used NAS servers for form pre-fill. Passwords are never stored.

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
      "last_used": "2026-06-18T02:00:05+00:00"
    }
  ]
}
```

Sorted newest first. Same host with a different path is a separate entry.

---

## 18–21. Restore Schedule

Daily automated restore from TimescaleDB → Production DB. Persisted to `restore_schedule.json`.

### Modes

| Mode | What it does | Required fields |
|------|-------------|-----------------|
| `full` | (default) Restores all rows from Backup DB | — |
| `limit` | Restores the N most-recent rows | `limit` |
| `hours` | Restores rows from the last N hours | `hours` |
| `range` | Restores rows between two datetimes | `start`, `end` |

### 18. POST /downlink/guardian/restore/schedule

Requires Bearer token. Returns **409** if a schedule already exists.

```bash
# Full restore nightly
curl -X POST "http://localhost:4567/downlink/guardian/restore/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "03:00", "timezone": "Asia/Kolkata", "mode": "full"}'

# Last 24 hours
curl -X POST "http://localhost:4567/downlink/guardian/restore/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "03:00", "timezone": "Asia/Kolkata", "mode": "hours", "hours": 24}'

# Fixed range
curl -X POST "http://localhost:4567/downlink/guardian/restore/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"time": "03:00", "timezone": "UTC", "mode": "range", "start": "2026-06-01T00:00:00", "end": "2026-06-18T23:59:59"}'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "03:00",
  "timezone": "Asia/Kolkata",
  "mode": "full",
  "next_run": "2026-06-19T03:00:00+05:30",
  "note": "Restore runs daily at the specified time. Persisted — survives API restarts."
}
```

409 response:
```json
{"detail": "A restore schedule already exists. DELETE /downlink/guardian/restore/schedule first."}
```

### 19. GET /downlink/guardian/restore/schedule

```bash
curl "http://localhost:4567/downlink/guardian/restore/schedule"
```

### 20. DELETE /downlink/guardian/restore/schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/restore/schedule"
```

Response:
```json
{"status": "Restore schedule removed"}
```

### 21. GET /downlink/guardian/restore/history

```bash
curl "http://localhost:4567/downlink/guardian/restore/history?limit=20"
```

---

## 22–24. Secure Export (Manual)

### 22. POST /downlink/guardian/secure-export

Exports Production DB → AES-256-GCM encrypt → SHA256 → SFTP to NAS. Hard-capped at **200,000 rows** (~10 seconds). For larger exports, use `POST /downlink/guardian/nas-backup/schedule`.

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
  "mode": "limit:200000",
  "total_rows": 95390,
  "total_batches": 10,
  "duration_seconds": 1.67,
  "export_path": "/home/honeycomb/test-nas-backup/export_20260618_093045"
}
```

Each export creates a timestamped subfolder (`export_YYYYMMDD_HHMMSS`) so multiple exports never overwrite each other. Use `export_path` as `remote_path` in import and preview calls.

### 23. POST /downlink/guardian/secure-export/list

Lists all export folders on the NAS under the base path.

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
      "folder": "export_20260618_093045",
      "export_path": "/home/honeycomb/test-nas-backup/export_20260618_093045",
      "exported_at": "2026-06-18T09:30:45+00:00",
      "total_rows": 95390,
      "total_batches": 10
    },
    {
      "folder": "export_20260617_120000",
      "export_path": "/home/honeycomb/test-nas-backup/export_20260617_120000",
      "exported_at": "2026-06-17T12:00:00+00:00",
      "total_rows": 90000,
      "total_batches": 9
    }
  ]
}
```

Returns newest first. Copy `export_path` and pass it as `remote_path` to import or preview.

### 24. POST /downlink/guardian/secure-export/preview

Decrypts a single batch file from NAS in memory and returns rows — **no DB write**.

```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-export/preview" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup/export_20260618_093045",
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
    {"time": "1700000000", "channel": "531a610d-...", "name": "temp", "value": "22.5"}
  ]
}
```

- `batch` — 0-based index (check `manifest.json` for total batch count)
- `rows` — how many rows to return (1–1000)

---

## 25–26. Secure Import (Manual)

Both manual import endpoints are hard-capped at **50,000 rows**. For larger imports use the scheduled import endpoints (27–32). The `remote_path` must point to a specific export folder, not the base path — use `/secure-export/list` to find the right path.

### 25. POST /downlink/guardian/secure-import/backup-db

Imports from NAS → TimescaleDB (Backup DB).

```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup/export_20260618_093045"
  }'
```

Response:
```json
{
  "status": "SUCCESS",
  "target": "backup",
  "batches_verified": 5,
  "rows_inserted": 50000,
  "duration_seconds": 18.4
}
```

### 26. POST /downlink/guardian/secure-import/production-db

Imports from NAS → Production DB (Magistrala).

```bash
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/production-db" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/test-nas-backup/export_20260618_093045"
  }'
```

Response:
```json
{
  "status": "SUCCESS",
  "target": "production",
  "batches_verified": 5,
  "rows_inserted": 50000,
  "duration_seconds": 19.1
}
```


---

## 27–29. Secure Import — Backup DB Schedule

Daily automated import from NAS → TimescaleDB (Backup DB). On each run the scheduler automatically finds the **latest** `export_*` folder under `remote_path` — no need to update the schedule when a new export is created. Optionally pin a specific folder using the `folder` field. Persisted to `import_backup_schedule.json`.

### Modes

| Mode | What it does | Required fields |
|------|-------------|-----------------|
| `full` | (default) Imports all rows from the export folder | — |
| `limit` | Imports the first N rows | `limit` |
| `hours` | Imports rows with `update_time` in the last N hours | `hours` |
| `range` | Imports rows with `update_time` between two datetimes | `start`, `end` |

### Folder selection

| `folder` field | Behaviour |
|----------------|-----------|
| Omitted (default) | Auto-picks the **latest** `export_*` subfolder under `remote_path` each run |
| `"export_20260618_232000"` | Always imports from that specific folder every run |

> **Tip:** If your NAS backup runs in `mode=limit` or `mode=range`, the latest export folder may be partial. Pin the specific full-export folder using `folder` to guarantee complete data.

### 27. POST /downlink/guardian/secure-import/backup-db/schedule

Requires Bearer token. Returns **409** if a schedule already exists — DELETE it first.

```bash
# Full import nightly (auto-picks latest export folder)
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "04:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "full"
  }'

# Pin a specific export folder (use when latest export is partial)
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "04:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "folder": "export_20260618_232000",
    "mode": "full"
  }'

# Last 24 hours nightly
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "04:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "hours", "hours": 24
  }'

# Last 100,000 rows nightly
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "04:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "limit", "limit": 100000
  }'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "04:00",
  "timezone": "Asia/Kolkata",
  "target": "backup",
  "mode": "full",
  "remote_path": "/home/honeycomb/backups",
  "next_run": "2026-06-19T04:00:00+05:30",
  "note": "Import runs daily. Auto-selects the latest export folder under remote_path."
}
```

409 response:
```json
{"detail": "An import-backup-db schedule already exists. DELETE /downlink/guardian/secure-import/backup-db/schedule first."}
```

### 28. GET /downlink/guardian/secure-import/backup-db/schedule

```bash
curl "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule"
```

Response:
```json
{
  "scheduled": true,
  "schedule": {
    "time": "04:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "remote_path": "/home/honeycomb/backups",
    "mode": "full",
    "target": "backup"
  },
  "next_run": "2026-06-19T04:00:00+05:30"
}
```

### 29. DELETE /downlink/guardian/secure-import/backup-db/schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/secure-import/backup-db/schedule"
```

Response:
```json
{"status": "Import-backup-db schedule removed"}
```

---

## 30–32. Secure Import — Production DB Schedule

Daily automated import from NAS → Production DB (Magistrala). Same behavior as the backup-db import schedule but targets the production database. Persisted to `import_production_schedule.json`.

### Modes

Same four modes: `full`, `limit`, `hours`, `range` — identical behavior as the backup-db schedule. `folder` field also works the same way (omit to auto-pick latest, or specify a folder name to pin it).

### 30. POST /downlink/guardian/secure-import/production-db/schedule

Requires Bearer token. Returns **409** if a schedule already exists — DELETE it first.

```bash
# Full import nightly (auto-picks latest export folder)
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/production-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "05:00",
    "timezone": "Asia/Kolkata",
    "host": "192.168.1.15",
    "port": 22,
    "username": "honeycomb",
    "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "full"
  }'

# Pin a specific export folder
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/production-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "05:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "folder": "export_20260618_232000",
    "mode": "full"
  }'

# Last 24 hours nightly
curl -X POST "http://localhost:4567/downlink/guardian/secure-import/production-db/schedule" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "time": "05:00", "timezone": "Asia/Kolkata",
    "host": "192.168.1.15", "port": 22,
    "username": "honeycomb", "password": "your-password",
    "remote_path": "/home/honeycomb/backups",
    "mode": "hours", "hours": 24
  }'
```

Response:
```json
{
  "status": "Scheduled",
  "time": "05:00",
  "timezone": "Asia/Kolkata",
  "target": "production",
  "mode": "full",
  "remote_path": "/home/honeycomb/backups",
  "next_run": "2026-06-19T05:00:00+05:30",
  "note": "Import runs daily. Auto-selects the latest export folder under remote_path."
}
```

409 response:
```json
{"detail": "An import-production-db schedule already exists. DELETE /downlink/guardian/secure-import/production-db/schedule first."}
```

### 31. GET /downlink/guardian/secure-import/production-db/schedule

```bash
curl "http://localhost:4567/downlink/guardian/secure-import/production-db/schedule"
```

### 32. DELETE /downlink/guardian/secure-import/production-db/schedule

```bash
curl -X DELETE "http://localhost:4567/downlink/guardian/secure-import/production-db/schedule"
```

Response:
```json
{"status": "Import-production-db schedule removed"}
```

---

## Hard Caps on Manual Triggers

| Endpoint | Cap | Reason |
|----------|-----|--------|
| `POST /downlink/guardian/backup` | 50,000 rows | Prevents frontend timeout |
| `POST /downlink/guardian/secure-export` | 200,000 rows (~10 sec) | Prevents frontend timeout |
| `POST /downlink/guardian/secure-import/backup-db` | 50,000 rows | Prevents frontend timeout |
| `POST /downlink/guardian/secure-import/production-db` | 50,000 rows | Prevents frontend timeout |
| All scheduled endpoints | No cap | Run in background — no timeout constraint |

---

## 409 Conflict Protection

All `POST .../schedule` endpoints return **409 Conflict** if a schedule is already active. To change a schedule: DELETE the existing one first, then POST the new one.

| Schedule | Persistence File |
|----------|-----------------|
| Backup schedule | `schedule.json` |
| NAS backup schedule | `nas_schedule.json` |
| Restore schedule | `restore_schedule.json` |
| Secure import → backup-db | `import_backup_schedule.json` |
| Secure import → production-db | `import_production_schedule.json` |

---

## Failure Alerts

When any scheduled job fails, an email alert is sent to the user who set the schedule. The recipient is resolved from the Bearer token used when calling the POST schedule endpoint — their `login_alert_email` from the users table is used. No extra configuration needed.

Alert conditions:
- Either DB is unreachable
- Script throws an exception
- Operation exceeds the 1-hour timeout

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

Stores `last_synced_time` and `last_message_time` (watermark) used by incremental sync.

---

## What Gets Written to the Remote Server

```
remote_path/
├── export_20260618_120000/        ← each export in its own timestamped folder
│   ├── manifest.json              # row counts, checksums, export timestamp, mode
│   ├── batch_000000.enc           # AES-256-GCM encrypted batch (rows 0–9999)
│   ├── batch_000000.sha256        # SHA256 of the encrypted file
│   ├── batch_000001.enc
│   ├── batch_000001.sha256
│   └── ...
└── export_20260619_120000/        ← next day — never overwrites previous
```

Encryption format per batch file:

```
[12 bytes — random nonce] [N bytes — ciphertext + 16-byte GCM tag]
```

SHA256 is computed over the full encrypted file (nonce + ciphertext + tag). Any corruption or tampering is caught before decryption.

---

## Security

| Concern | Approach |
|---------|----------|
| Data confidentiality | AES-256-GCM per batch — unique random nonce per batch |
| Transfer integrity | SHA256 verified before decryption on every import |
| Authenticated encryption | GCM tag detects ciphertext tampering without a separate HMAC |
| Transport security | SFTP over SSH — no plaintext ever leaves the host |
| Key management | Key in `BACKUP_ENCRYPTION_KEY` env var only — never written to disk or logs |
| Password storage | SSH passwords AES-encrypted at rest in schedule JSON files |

---

## Known Behaviours

| Behaviour | Detail |
|-----------|--------|
| Float epoch strings | Source DB may return `update_time` as `0.0` — handled with `int(float(...))` |
| NULL subtopic | Production DB requires `subtopic NOT NULL` — rows with NULL subtopic default to `''` on import |
| SSH key scanning disabled | paramiko uses password-only auth (`look_for_keys=False`, `allow_agent=False`) |
| Sync timeout | All sync/restore/import operations have a 1-hour max timeout |
| Scheduled import folder | Import schedules open a temporary SFTP connection to find the latest `export_*` folder, then pass it to `secure_import()` — two SFTP connections per run |
| Watermark reset on full mode | Backup schedule with `mode=full` sets `last_message_time = NULL` so sync.py fetches all rows |
| Manual backup cap | `POST /downlink/guardian/backup` caps at 50,000 rows — use the schedule for full incremental sync |
| Scheduled backup alerts | Failure email goes to the user who set the schedule, resolved from Bearer token via `login_alert_email` |

---

## CLI Usage

```bash
# Production DB → TimescaleDB (incremental)
python sync.py

# TimescaleDB → Production DB (full)
python reverse_sync.py

# TimescaleDB → Production DB (last 24 hours)
python reverse_sync.py 24

# TimescaleDB → Production DB (last 500 rows)
python reverse_sync.py --limit 500

# Export to NAS
export BACKUP_ENCRYPTION_KEY=<key>
python secure_export.py <host> <port> <username> <password> <remote_path>

# Import from NAS into TimescaleDB
python secure_import.py <host> <port> <username> <password> <remote_path> backup

# Import from NAS into Production DB
python secure_import.py <host> <port> <username> <password> <remote_path> production
```

---

## Manually Decrypt a Batch File

```python
from transfer_utils import decrypt, load_key
import gzip

key = load_key()
with open('/tmp/batch_000000.enc', 'rb') as f:
    encrypted = f.read()

plaintext = gzip.decompress(decrypt(encrypted, key))
lines = plaintext.decode('utf-8').splitlines()
print(f'Total rows: {len(lines) - 1}')
for line in lines[:6]:
    print(line)
```

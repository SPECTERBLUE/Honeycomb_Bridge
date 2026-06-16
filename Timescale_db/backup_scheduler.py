"""
backup_scheduler.py — Singleton APScheduler for daily automated backups.

Import this module wherever you need to start the scheduler or manage the schedule.
Call start_backup_scheduler() once at startup (from main.py or api startup).

SMTP alerts: reads SMTP credentials from the parent project's config.py automatically.
On failure the alert goes to SMTP_USERNAME (same as sender) unless
BACKUP_ALERT_EMAIL env var is set to override the recipient.
"""

import atexit
import json
import logging
import os
import smtplib
import subprocess
import sys
from datetime import datetime, timezone
from email.mime.text import MIMEText

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_HERE = os.path.dirname(os.path.abspath(__file__))
SCHEDULE_FILE = os.path.join(_HERE, "schedule.json")
NAS_SCHEDULE_FILE = os.path.join(_HERE, "nas_schedule.json")
SYNC_SCRIPT = os.path.join(_HERE, "sync.py")
BACKUP_HISTORY_FILE = os.path.join(_HERE, "backup_history.json")
NAS_HISTORY_FILE = os.path.join(_HERE, "nas_history.json")
_HISTORY_MAX = 100


def _append_history(file_path: str, entry: dict) -> None:
    try:
        history = []
        if os.path.exists(file_path):
            with open(file_path) as f:
                history = json.load(f)
        history.append(entry)
        if len(history) > _HISTORY_MAX:
            history = history[-_HISTORY_MAX:]
        with open(file_path, "w") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

_log = logging.getLogger("backup_scheduler")

# ── SMTP — load credentials from parent project's config.py ─
_SMTP_SERVER = ""
_SMTP_PORT = 587
_SMTP_USER = ""
_SMTP_PASS = ""

try:
    _parent = os.path.dirname(_HERE)
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    import config as _cfg
    _SMTP_SERVER = getattr(_cfg, "SMTP_SERVER", "")
    _SMTP_PORT   = getattr(_cfg, "SMTP_PORT",   587)
    _SMTP_USER   = getattr(_cfg, "SMTP_USERNAME", "")
    _SMTP_PASS   = getattr(_cfg, "SMTP_PASSWORD", "")
except Exception:
    pass

_SMTP_READY = bool(_SMTP_SERVER and _SMTP_USER and _SMTP_PASS)


def _get_alert_emails(schedule_file: str = None) -> list[str]:
    """Read login_alert_email for the user who set the schedule."""
    if schedule_file is None:
        schedule_file = SCHEDULE_FILE
    try:
        if not os.path.exists(schedule_file):
            _log.warning(f"{os.path.basename(schedule_file)} not found — cannot determine alert recipient")
            return []

        with open(schedule_file) as f:
            saved = json.load(f)

        user_id = saved.get("user_id")
        if not user_id:
            _log.warning(f"No user_id in {os.path.basename(schedule_file)} — cannot determine alert recipient")
            return []

        import psycopg2
        sys.path.insert(0, _HERE)
        from db_config import APP_DB_URL
        if not APP_DB_URL:
            raise RuntimeError("DATABASE_URL env var is not set")
        conn = psycopg2.connect(APP_DB_URL)
        cur = conn.cursor()
        cur.execute("""
            SELECT login_alert_email FROM users
            WHERE id = %s
              AND login_alert_email IS NOT NULL
              AND login_alert_email != ''
        """, (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return [row[0]] if row else []
    except Exception as e:
        _log.warning(f"Could not read login_alert_email from users table: {e}")
        return []


def _send_alert(subject: str, body: str, schedule_file: str = None) -> None:
    """Send a failure alert to the user who set the schedule."""
    if not _SMTP_READY:
        return
    recipients = _get_alert_emails(schedule_file)
    if not recipients:
        _log.warning("No login_alert_email found in users table — skipping alert.")
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = _SMTP_USER
        msg["To"] = ", ".join(recipients)
        with smtplib.SMTP(_SMTP_SERVER, _SMTP_PORT) as server:
            server.starttls()
            server.login(_SMTP_USER, _SMTP_PASS)
            server.send_message(msg)
        _log.info(f"Alert sent to {recipients}: {subject}")
    except Exception as exc:
        _log.error(f"Failed to send alert email: {exc}")


if _AVAILABLE:
    _scheduler = BackgroundScheduler(daemon=True)

    def _run_job():
        import time as _time
        start_ts = datetime.now(timezone.utc)
        start_wall = _time.monotonic()
        try:
            result = subprocess.run(
                [sys.executable, SYNC_SCRIPT],
                capture_output=True, text=True, timeout=3600,
            )
            duration = round(_time.monotonic() - start_wall, 2)
            output = (result.stdout + result.stderr).strip()
            if result.returncode != 0:
                _log.error(f"Scheduled backup FAILED:\n{output}")
                _append_history(BACKUP_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "duration_seconds": duration,
                    "source_count": None,
                    "backup_count": None,
                })
                _send_alert(
                    "[TimescaleDB] Scheduled Backup FAILED",
                    f"Your scheduled database backup has FAILED.\n"
                    f"Script : {SYNC_SCRIPT}\n"
                    f"\n"
                    f"---- Possible Causes ----\n"
                    f"1. Backup DB (TimescaleDB) is down or unreachable (port 5436).\n"
                    f"2. Source DB (Magistrala) is down or unreachable (port 5433).\n"
                    f"3. Network connectivity issue between services.\n"
                    f"4. DB credentials changed or permission denied.\n"
                    f"5. Disk space full on the backup server.\n"
                    f"6. Backup timed out (limit: 3600s) — dataset may be too large.\n"
                    f"\n"
                    f"Please check the server logs for full details.",
                )
            else:
                _log.info(f"Scheduled backup completed:\n{output}")
                source_count, backup_count = None, None
                try:
                    import psycopg2
                    sys.path.insert(0, _HERE)
                    from db_config import SOURCE_DB, TARGET_DB
                    src = psycopg2.connect(**SOURCE_DB)
                    src_cur = src.cursor()
                    src_cur.execute("SELECT COUNT(*) FROM messages")
                    source_count = src_cur.fetchone()[0]
                    src_cur.close(); src.close()
                    tgt = psycopg2.connect(**TARGET_DB)
                    tgt_cur = tgt.cursor()
                    tgt_cur.execute("SELECT COUNT(*) FROM messages")
                    backup_count = tgt_cur.fetchone()[0]
                    tgt_cur.close(); tgt.close()
                except Exception:
                    pass
                _append_history(BACKUP_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "SUCCESS",
                    "duration_seconds": duration,
                    "source_count": source_count,
                    "backup_count": backup_count,
                })
        except Exception as exc:
            duration = round(_time.monotonic() - start_wall, 2)
            _log.error(f"Scheduled backup exception: {exc}")
            _append_history(BACKUP_HISTORY_FILE, {
                "start_time": start_ts.isoformat(),
                "status": "FAILED",
                "duration_seconds": duration,
                "source_count": None,
                "backup_count": None,
            })
            _send_alert(
                "[TimescaleDB] Scheduled Backup FAILED",
                f"Your scheduled database backup raised an unexpected exception.\n"
                f"Script : {SYNC_SCRIPT}\n"
                f"\n"
                f"---- Possible Causes ----\n"
                f"1. Backup DB (TimescaleDB) is down or unreachable (port 5436).\n"
                f"2. Source DB (Magistrala) is down or unreachable (port 5433).\n"
                f"3. Network connectivity issue between services.\n"
                f"4. DB credentials changed or permission denied.\n"
                f"5. Disk space full on the backup server.\n"
                f"6. Backup timed out (limit: 3600s) — dataset may be too large.\n"
                f"\n"
                f"Please check the server logs for full details.",
            )

    def apply_schedule(time_str: str, tz_str: str = "UTC") -> None:
        """Register (or replace) the daily backup cron job."""
        h, m = map(int, time_str.split(":"))
        _scheduler.add_job(
            _run_job,
            trigger=CronTrigger(hour=h, minute=m, timezone=tz_str),
            id="daily_backup",
            replace_existing=True,
        )

    def apply_nas_schedule(time_str: str, tz_str: str, host: str, port: int,
                           username: str, password: str, remote_path: str) -> None:
        """Register (or replace) the daily NAS backup cron job."""
        h, m = map(int, time_str.split(":"))

        def _run_nas_job():
            import time as _time
            start_ts = datetime.now(timezone.utc)
            start_wall = _time.monotonic()
            try:
                sys.path.insert(0, _HERE)
                from secure_export import secure_export
                result = secure_export(
                    host=host, port=port,
                    username=username, password=password,
                    remote_path=remote_path,
                )
                duration = round(_time.monotonic() - start_wall, 2)
                _log.info(f"Scheduled NAS backup completed: {result}")
                _append_history(NAS_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "SUCCESS",
                    "duration_seconds": result.get("duration_seconds", duration),
                    "total_rows": result.get("total_rows"),
                    "total_batches": result.get("total_batches"),
                    "target": f"{username}@{host}:{port}{remote_path}",
                })
            except Exception as exc:
                duration = round(_time.monotonic() - start_wall, 2)
                _log.error(f"Scheduled NAS backup FAILED: {exc}")
                _append_history(NAS_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "duration_seconds": duration,
                    "total_rows": None,
                    "total_batches": None,
                    "target": f"{username}@{host}:{port}{remote_path}",
                })
                _send_alert(
                    "[TimescaleDB] Scheduled NAS Backup FAILED",
                    f"Your scheduled NAS backup has FAILED.\n"
                    f"Target : {username}@{host}:{port}{remote_path}\n"
                    f"\n"
                    f"---- Possible Causes ----\n"
                    f"1. NAS / SSH server is unreachable (host: {host}, port: {port}).\n"
                    f"2. SSH credentials changed or permission denied.\n"
                    f"3. Remote path does not exist and could not be created.\n"
                    f"4. Disk space full on the NAS.\n"
                    f"5. Source DB (Magistrala) is down or unreachable.\n"
                    f"6. Encryption key (BACKUP_ENCRYPTION_KEY) is not set.\n"
                    f"\n"
                    f"Please check the server logs for full details.",
                    NAS_SCHEDULE_FILE,
                )

        _scheduler.add_job(
            _run_nas_job,
            trigger=CronTrigger(hour=h, minute=m, timezone=tz_str),
            id="daily_nas_backup",
            replace_existing=True,
        )

    def start_backup_scheduler() -> None:
        """
        Start the scheduler and restore any saved schedule from schedule.json.
        Safe to call multiple times — no-op if already running.
        Call this once at application startup.
        """
        if _scheduler.running:
            return

        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE) as f:
                    saved = json.load(f)
                apply_schedule(saved["time"], saved.get("timezone", "UTC"))
                _log.info(
                    f"Restored backup schedule: {saved['time']} "
                    f"({saved.get('timezone', 'UTC')})"
                )
            except Exception as e:
                _log.warning(f"Could not restore saved schedule: {e}")

        if os.path.exists(NAS_SCHEDULE_FILE):
            try:
                with open(NAS_SCHEDULE_FILE) as f:
                    saved = json.load(f)
                import base64
                sys.path.insert(0, _HERE)
                from transfer_utils import decrypt, load_key
                raw_pw = base64.b64decode(saved["password"])
                password = decrypt(raw_pw, load_key()).decode()
                apply_nas_schedule(
                    saved["time"], saved.get("timezone", "UTC"),
                    saved["host"], saved["port"],
                    saved["username"], password,
                    saved["remote_path"],
                )
                _log.info(
                    f"Restored NAS backup schedule: {saved['time']} "
                    f"({saved.get('timezone', 'UTC')}) → {saved['host']}"
                )
            except Exception as e:
                _log.warning(f"Could not restore saved NAS schedule: {e}")

        _scheduler.start()
        atexit.register(lambda: _scheduler.shutdown(wait=False))
        _log.info(
            f"Backup scheduler started. "
            f"SMTP alerts: {'enabled' if _SMTP_READY else 'disabled (no SMTP config)'}"
        )

else:
    _scheduler = None

    def apply_schedule(*_args, **_kwargs) -> None:
        raise RuntimeError("APScheduler not installed. Run: pip install apscheduler")

    def start_backup_scheduler() -> None:
        _log.warning(
            "APScheduler not installed — backup scheduler not started. "
            "Run: pip install apscheduler"
        )

"""
backup_scheduler.py — Singleton APScheduler for daily automated backups.

Import this module wherever you need to start the scheduler or manage the schedule.
Call start_backup_scheduler() once at startup (from main.py or api startup).

SMTP alerts: reads SMTP credentials from the parent project's config.py automatically.
On failure the alert goes to SMTP_USERNAME (same as sender) unless
BACKUP_ALERT_EMAIL env var is set to override the recipient.
"""

import atexit
import base64
import json
import logging
import os
import re
import smtplib
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import psycopg2
from psycopg2.extras import execute_batch
from db_config import APP_DB_URL, SOURCE_DB, TARGET_DB, get_source_conn, get_target_conn
from secure_export import secure_export
from secure_import import secure_import, find_latest_export
from transfer_utils import decrypt, load_key, sftp_connect

SCHEDULE_FILE = os.path.join(_HERE, "schedule.json")
NAS_SCHEDULE_FILE = os.path.join(_HERE, "nas_schedule.json")
RESTORE_SCHEDULE_FILE = os.path.join(_HERE, "restore_schedule.json")
IMPORT_BACKUP_SCHEDULE_FILE = os.path.join(_HERE, "import_backup_schedule.json")
IMPORT_PRODUCTION_SCHEDULE_FILE = os.path.join(_HERE, "import_production_schedule.json")
IMPORT_BACKUP_HISTORY_FILE = os.path.join(_HERE, "import_backup_history.json")
IMPORT_PRODUCTION_HISTORY_FILE = os.path.join(_HERE, "import_production_history.json")
SYNC_SCRIPT = os.path.join(_HERE, "sync.py")
RESTORE_SCRIPT = os.path.join(_HERE, "reverse_sync.py")
BACKUP_HISTORY_FILE = os.path.join(_HERE, "backup_history.json")
NAS_HISTORY_FILE = os.path.join(_HERE, "nas_history.json")
RESTORE_HISTORY_FILE = os.path.join(_HERE, "restore_history.json")
_HISTORY_MAX = 1000


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

    def apply_schedule(time_str: str, tz_str: str = "UTC", mode: str = "incremental", **kwargs) -> None:
        """Register (or replace) the daily backup cron job.
        mode: incremental | full | limit | hours | range
        """
        h, m = map(int, time_str.split(":"))

        def _run_backup_job():
            start_ts = datetime.now(timezone.utc)
            start_wall = time.monotonic()
            try:
                # ── subprocess modes: incremental / full ────────────────────────
                if mode in ("incremental", "full"):
                    if mode == "full":
                        # Reset watermark so sync.py performs a complete re-sync
                        try:
                            _tgt = psycopg2.connect(**TARGET_DB)
                            _tc = _tgt.cursor()
                            _tc.execute("UPDATE backup_metadata SET last_message_time = NULL WHERE id = TRUE")
                            _tgt.commit()
                            _tc.close()
                            _tgt.close()
                        except Exception as wm_exc:
                            _log.warning(f"Could not reset watermark for full backup: {wm_exc}")

                    result = subprocess.run(
                        [sys.executable, SYNC_SCRIPT],
                        capture_output=True, text=True, timeout=3600,
                    )
                    duration = round(time.monotonic() - start_wall, 2)
                    output = (result.stdout + result.stderr).strip()

                    if result.returncode != 0:
                        _log.error(f"Scheduled backup ({mode}) FAILED:\n{output}")
                        _append_history(BACKUP_HISTORY_FILE, {
                            "start_time": start_ts.isoformat(),
                            "status": "FAILED",
                            "mode": mode,
                            "duration_seconds": duration,
                            "source_count": None,
                            "backup_count": None,
                        })
                        _send_alert(
                            f"[TimescaleDB] Scheduled Backup ({mode.upper()}) FAILED",
                            f"Your scheduled database backup has FAILED.\n"
                            f"Mode   : {mode}\n"
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
                        _log.info(f"Scheduled backup ({mode}) completed:\n{output}")
                        source_count, backup_count = None, None
                        try:
                            src = psycopg2.connect(**SOURCE_DB)
                            src_cur = src.cursor()
                            src_cur.execute("SELECT COUNT(*) FROM messages")
                            source_count = src_cur.fetchone()[0]
                            src_cur.close()
                            src.close()
                            tgt = psycopg2.connect(**TARGET_DB)
                            tgt_cur = tgt.cursor()
                            tgt_cur.execute("SELECT COUNT(*) FROM messages")
                            backup_count = tgt_cur.fetchone()[0]
                            tgt_cur.close()
                            tgt.close()
                        except Exception:
                            pass
                        _append_history(BACKUP_HISTORY_FILE, {
                            "start_time": start_ts.isoformat(),
                            "status": "SUCCESS",
                            "mode": mode,
                            "duration_seconds": duration,
                            "source_count": source_count,
                            "backup_count": backup_count,
                        })

                # ── inline modes: limit / hours / range ────────────────────────
                else:
                    # Check backup_control.enabled before running
                    try:
                        _tgt_ctrl = psycopg2.connect(**TARGET_DB)
                        _tc = _tgt_ctrl.cursor()
                        _tc.execute("SELECT enabled FROM backup_control WHERE id = TRUE")
                        _ctrl_row = _tc.fetchone()
                        _tc.close()
                        _tgt_ctrl.close()
                        if not _ctrl_row or _ctrl_row[0] is not True:
                            _log.warning(f"Backup disabled — skipping scheduled {mode} backup")
                            return
                    except Exception as ctrl_exc:
                        _log.warning(f"Could not read backup_control: {ctrl_exc}")

                    FETCH_SIZE = 10000
                    BATCH_SIZE = 10000
                    total_fetched = 0
                    total_upserted = 0

                    src_conn = get_source_conn()
                    tgt_conn = get_target_conn()
                    src_cur = src_conn.cursor(name="sched_backup_cursor")
                    tgt_cur = tgt_conn.cursor()

                    insert_sql = """
                        INSERT INTO messages (
                            time, channel, subtopic, publisher, protocol,
                            name, unit, value, string_value, bool_value,
                            data_value, sum, update_time
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (time, publisher, subtopic, name) DO UPDATE SET
                            channel      = EXCLUDED.channel,
                            protocol     = EXCLUDED.protocol,
                            unit         = EXCLUDED.unit,
                            value        = EXCLUDED.value,
                            string_value = EXCLUDED.string_value,
                            bool_value   = EXCLUDED.bool_value,
                            data_value   = EXCLUDED.data_value,
                            sum          = EXCLUDED.sum,
                            update_time  = EXCLUDED.update_time
                    """

                    try:
                        if mode == "limit":
                            src_cur.execute("""
                                SELECT * FROM (
                                    SELECT
                                        time, channel, subtopic, publisher, protocol,
                                        name, unit, value, string_value, bool_value,
                                        data_value, sum,
                                        COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                                    FROM messages
                                    ORDER BY COALESCE(NULLIF(update_time, 0), time) DESC
                                    LIMIT %s
                                ) t ORDER BY update_time_epoch
                            """, (kwargs["limit"],))
                        elif mode == "hours":
                            cutoff = int(datetime.now(timezone.utc).timestamp()) - kwargs["hours"] * 3600
                            src_cur.execute("""
                                SELECT
                                    time, channel, subtopic, publisher, protocol,
                                    name, unit, value, string_value, bool_value,
                                    data_value, sum,
                                    COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                                FROM messages
                                WHERE COALESCE(NULLIF(update_time, 0), time) > %s
                                ORDER BY update_time_epoch
                            """, (cutoff,))
                        elif mode == "range":
                            start_epoch = int(kwargs["start_dt"].timestamp())
                            end_epoch = int(kwargs["end_dt"].timestamp())
                            src_cur.execute("""
                                SELECT
                                    time, channel, subtopic, publisher, protocol,
                                    name, unit, value, string_value, bool_value,
                                    data_value, sum,
                                    COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                                FROM messages
                                WHERE COALESCE(NULLIF(update_time, 0), time) BETWEEN %s AND %s
                                ORDER BY update_time_epoch
                            """, (start_epoch, end_epoch))

                        buffer = []
                        while True:
                            rows = src_cur.fetchmany(FETCH_SIZE)
                            if not rows:
                                break
                            total_fetched += len(rows)
                            for r in rows:
                                row = list(r)
                                epoch_val = row[-1]
                                ts_val = (
                                    datetime.fromtimestamp(epoch_val, timezone.utc)
                                    if epoch_val is not None
                                    else datetime.now(timezone.utc)
                                )
                                buffer.append(tuple(list(row[:-1]) + [ts_val]))

                            while len(buffer) >= BATCH_SIZE:
                                batch = buffer[:BATCH_SIZE]
                                execute_batch(tgt_cur, insert_sql, batch)
                                tgt_conn.commit()
                                total_upserted += len(batch)
                                buffer = buffer[BATCH_SIZE:]

                        if buffer:
                            execute_batch(tgt_cur, insert_sql, buffer)
                            tgt_conn.commit()
                            total_upserted += len(buffer)

                    finally:
                        src_cur.close()
                        tgt_cur.close()
                        src_conn.close()
                        tgt_conn.close()

                    duration = round(time.monotonic() - start_wall, 2)
                    _log.info(
                        f"Scheduled backup ({mode}) completed: "
                        f"fetched={total_fetched}, upserted={total_upserted}"
                    )
                    _append_history(BACKUP_HISTORY_FILE, {
                        "start_time": start_ts.isoformat(),
                        "status": "SUCCESS",
                        "mode": mode,
                        "duration_seconds": duration,
                        "rows_fetched": total_fetched,
                        "rows_upserted": total_upserted,
                    })

            except Exception as exc:
                duration = round(time.monotonic() - start_wall, 2)
                _log.error(f"Scheduled backup ({mode}) exception: {exc}")
                _append_history(BACKUP_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "mode": mode,
                    "duration_seconds": duration,
                    "source_count": None,
                    "backup_count": None,
                })
                _send_alert(
                    f"[TimescaleDB] Scheduled Backup ({mode.upper()}) FAILED",
                    f"Your scheduled database backup raised an unexpected exception.\n"
                    f"Mode   : {mode}\n"
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

        _scheduler.add_job(
            _run_backup_job,
            trigger=CronTrigger(hour=h, minute=m, timezone=tz_str),
            id="daily_backup",
            replace_existing=True,
        )

    def apply_nas_schedule(time_str: str, tz_str: str, host: str, port: int,
                           username: str, password: str, remote_path: str,
                           mode: str = "full", **kwargs) -> None:
        """Register (or replace) the daily NAS backup cron job.
        mode: full | limit | hours | range
        """
        h, m = map(int, time_str.split(":"))

        def _run_nas_job():

            start_ts = datetime.now(timezone.utc)
            start_wall = time.monotonic()
            try:
                nas_kwargs = {}
                if mode == "limit":
                    nas_kwargs["limit"] = kwargs.get("limit")
                elif mode == "hours":
                    nas_kwargs["hours"] = kwargs.get("hours")
                elif mode == "range":
                    nas_kwargs["start_dt"] = kwargs.get("start_dt")
                    nas_kwargs["end_dt"] = kwargs.get("end_dt")

                result = secure_export(
                    host=host, port=port,
                    username=username, password=password,
                    remote_path=remote_path,
                    **nas_kwargs,
                )
                duration = round(time.monotonic() - start_wall, 2)
                _log.info(f"Scheduled NAS backup ({mode}) completed: {result}")
                _append_history(NAS_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "SUCCESS",
                    "mode": mode,
                    "duration_seconds": result.get("duration_seconds", duration),
                    "total_rows": result.get("total_rows"),
                    "total_batches": result.get("total_batches"),
                    "target": f"{username}@{host}:{port}{remote_path}",
                })
            except Exception as exc:
                duration = round(time.monotonic() - start_wall, 2)
                _log.error(f"Scheduled NAS backup ({mode}) FAILED: {exc}")
                _append_history(NAS_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "mode": mode,
                    "duration_seconds": duration,
                    "total_rows": None,
                    "total_batches": None,
                    "target": f"{username}@{host}:{port}{remote_path}",
                })
                _send_alert(
                    f"[TimescaleDB] Scheduled NAS Backup ({mode.upper()}) FAILED",
                    f"Your scheduled NAS backup has FAILED.\n"
                    f"Mode   : {mode}\n"
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

    def apply_restore_schedule(time_str: str, tz_str: str, mode: str, **kwargs) -> None:
        """Register (or replace) the daily restore cron job. mode: full | limit | hours | range"""
        h, m = map(int, time_str.split(":"))

        def _run_restore_job():
            start_ts = datetime.now(timezone.utc)
            start_wall = time.monotonic()
            try:
                if mode in ("full", "limit", "hours"):
                    cmd = [sys.executable, RESTORE_SCRIPT]
                    if mode == "limit":
                        cmd += ["--limit", str(kwargs["limit"])]
                    elif mode == "hours":
                        cmd += [str(kwargs["hours"])]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                    duration = round(time.monotonic() - start_wall, 2)
                    output = (result.stdout + result.stderr).strip()

                    if result.returncode != 0:
                        _log.error(f"Scheduled restore FAILED:\n{output}")
                        _append_history(RESTORE_HISTORY_FILE, {
                            "start_time": start_ts.isoformat(),
                            "status": "FAILED",
                            "mode": mode,
                            "duration_seconds": duration,
                            "rows_fetched": None,
                            "rows_inserted": None,
                        })
                        _send_alert(
                            "[TimescaleDB] Scheduled Restore FAILED",
                            f"Your scheduled restore has FAILED.\nMode: {mode}\n\nPlease check server logs.",
                            RESTORE_SCHEDULE_FILE,
                        )
                    else:
                        _log.info(f"Scheduled restore completed:\n{output}")
                        fetched_m = re.search(r"Records fetched\s*:\s*(\d+)", output)
                        inserted_m = re.search(r"Records inserted\s*:\s*(\d+)", output)
                        _append_history(RESTORE_HISTORY_FILE, {
                            "start_time": start_ts.isoformat(),
                            "status": "SUCCESS",
                            "mode": mode,
                            "duration_seconds": duration,
                            "rows_fetched": int(fetched_m.group(1)) if fetched_m else None,
                            "rows_inserted": int(inserted_m.group(1)) if inserted_m else None,
                        })

                elif mode == "range":
                    start_dt = kwargs["start_dt"]
                    end_dt = kwargs["end_dt"]
                    total_fetched = 0
                    total_inserted = 0

                    src_conn = get_source_conn()
                    tgt_conn = get_target_conn()
                    src_cur = src_conn.cursor()
                    tgt_cur = tgt_conn.cursor(name="sched_range_restore_cursor")

                    try:
                        tgt_cur.execute("""
                            SELECT time, channel, subtopic, publisher, protocol,
                                   name, unit, value, string_value, bool_value,
                                   data_value, sum, update_time
                            FROM messages
                            WHERE update_time >= %s AND update_time <= %s
                            ORDER BY update_time
                        """, (start_dt, end_dt))

                        insert_sql = """
                            INSERT INTO messages (
                                time, channel, subtopic, publisher, protocol,
                                name, unit, value, string_value, bool_value,
                                data_value, sum, update_time
                            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (time, publisher, subtopic, name) DO NOTHING
                        """

                        while True:
                            rows = tgt_cur.fetchmany(10000)
                            if not rows:
                                break
                            total_fetched += len(rows)
                            batch = []
                            for r in rows:
                                row = list(r)
                                row[-1] = row[-1].timestamp() if row[-1] is not None else None
                                batch.append(tuple(row))
                            execute_batch(src_cur, insert_sql, batch)
                            src_conn.commit()
                            total_inserted += len(batch)
                    finally:
                        tgt_cur.close()
                        src_cur.close()
                        tgt_conn.close()
                        src_conn.close()

                    duration = round(time.monotonic() - start_wall, 2)
                    _append_history(RESTORE_HISTORY_FILE, {
                        "start_time": start_ts.isoformat(),
                        "status": "SUCCESS",
                        "mode": mode,
                        "duration_seconds": duration,
                        "rows_fetched": total_fetched,
                        "rows_inserted": total_inserted,
                    })

            except Exception as exc:
                duration = round(time.monotonic() - start_wall, 2)
                _log.error(f"Scheduled restore exception: {exc}")
                _append_history(RESTORE_HISTORY_FILE, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "mode": mode,
                    "duration_seconds": duration,
                    "rows_fetched": None,
                    "rows_inserted": None,
                })
                _send_alert(
                    "[TimescaleDB] Scheduled Restore FAILED",
                    f"Your scheduled restore raised an unexpected exception.\nMode: {mode}\n\nPlease check server logs.",
                    RESTORE_SCHEDULE_FILE,
                )

        _scheduler.add_job(
            _run_restore_job,
            trigger=CronTrigger(hour=h, minute=m, timezone=tz_str),
            id="daily_restore",
            replace_existing=True,
        )

    def apply_import_schedule(time_str: str, tz_str: str, target: str,
                              host: str, port: int, username: str, password: str,
                              remote_base_path: str, mode: str = "full", **kwargs) -> None:
        """Register (or replace) a daily secure-import cron job.
        target: backup | production   mode: full | limit | hours | range
        Automatically imports from the latest export_* folder on the NAS each run.
        """
        if target not in ("backup", "production"):
            raise ValueError("target must be 'backup' or 'production'")

        job_id = f"daily_import_{target}"
        history_file = IMPORT_BACKUP_HISTORY_FILE if target == "backup" else IMPORT_PRODUCTION_HISTORY_FILE
        schedule_file = IMPORT_BACKUP_SCHEDULE_FILE if target == "backup" else IMPORT_PRODUCTION_SCHEDULE_FILE
        h, m = map(int, time_str.split(":"))

        folder = kwargs.pop("folder", None)

        def _run_import_job():
            start_ts = datetime.now(timezone.utc)
            start_wall = time.monotonic()
            export_path = None
            try:
                if folder:
                    export_path = f"{remote_base_path.rstrip('/')}/{folder}"
                else:
                    # Auto-pick the latest export_* folder on NAS
                    ssh_tmp, sftp_tmp = sftp_connect(host, port, username, password)
                    try:
                        export_path = find_latest_export(sftp_tmp, remote_base_path)
                    finally:
                        sftp_tmp.close()
                        ssh_tmp.close()

                import_kwargs = {}
                if mode == "limit":
                    import_kwargs["limit"] = kwargs.get("limit")
                elif mode == "hours":
                    import_kwargs["hours"] = kwargs.get("hours")
                elif mode == "range":
                    import_kwargs["start_dt"] = kwargs.get("start_dt")
                    import_kwargs["end_dt"] = kwargs.get("end_dt")

                result = secure_import(
                    host=host, port=port,
                    username=username, password=password,
                    remote_path=export_path,
                    target=target,
                    **import_kwargs,
                )
                duration = round(time.monotonic() - start_wall, 2)
                _log.info(f"Scheduled import ({target}, {mode}) completed: {result}")
                _append_history(history_file, {
                    "start_time": start_ts.isoformat(),
                    "status": "SUCCESS",
                    "target": target,
                    "mode": mode,
                    "export_path": export_path,
                    "duration_seconds": result.get("duration_seconds", duration),
                    "rows_inserted": result.get("rows_inserted"),
                    "batches_verified": result.get("batches_verified"),
                })
            except Exception as exc:
                duration = round(time.monotonic() - start_wall, 2)
                _log.error(f"Scheduled import ({target}, {mode}) FAILED: {exc}")
                _append_history(history_file, {
                    "start_time": start_ts.isoformat(),
                    "status": "FAILED",
                    "target": target,
                    "mode": mode,
                    "export_path": export_path,
                    "duration_seconds": duration,
                    "rows_inserted": None,
                })
                _send_alert(
                    f"[TimescaleDB] Scheduled Import ({target.upper()}) FAILED",
                    f"Your scheduled NAS import has FAILED.\n"
                    f"Target : {target}\nMode   : {mode}\n"
                    f"NAS    : {username}@{host}:{port}{remote_base_path}\n"
                    f"\n"
                    f"---- Possible Causes ----\n"
                    f"1. NAS / SSH server is unreachable.\n"
                    f"2. No export_* folders found under the base path.\n"
                    f"3. SHA256 checksum mismatch — corrupted export file.\n"
                    f"4. Encryption key (BACKUP_ENCRYPTION_KEY) changed or missing.\n"
                    f"5. Target DB is down or unreachable.\n"
                    f"\n"
                    f"Please check the server logs for full details.",
                    schedule_file,
                )

        _scheduler.add_job(
            _run_import_job,
            trigger=CronTrigger(hour=h, minute=m, timezone=tz_str),
            id=job_id,
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
                sched_mode = saved.get("mode", "incremental")
                sched_kwargs = {k: v for k, v in saved.items() if k not in ("time", "timezone", "mode", "user_id")}
                if sched_mode == "range":
                    sched_kwargs["start_dt"] = datetime.fromisoformat(saved["start_dt"])
                    sched_kwargs["end_dt"] = datetime.fromisoformat(saved["end_dt"])
                apply_schedule(saved["time"], saved.get("timezone", "UTC"), sched_mode, **sched_kwargs)
                _log.info(
                    f"Restored backup schedule: {saved['time']} "
                    f"({saved.get('timezone', 'UTC')}) mode={sched_mode}"
                )
            except Exception as e:
                _log.warning(f"Could not restore saved schedule: {e}")

        if os.path.exists(NAS_SCHEDULE_FILE):
            try:
                with open(NAS_SCHEDULE_FILE) as f:
                    saved = json.load(f)
                raw_pw = base64.b64decode(saved["password"])
                password = decrypt(raw_pw, load_key()).decode()
                nas_mode = saved.get("mode", "full")
                _skip = {"time", "timezone", "host", "port", "username", "password", "remote_path", "mode", "user_id"}
                nas_kwargs = {k: v for k, v in saved.items() if k not in _skip}
                if nas_mode == "range":
                    nas_kwargs["start_dt"] = datetime.fromisoformat(saved["start_dt"])
                    nas_kwargs["end_dt"] = datetime.fromisoformat(saved["end_dt"])
                apply_nas_schedule(
                    saved["time"], saved.get("timezone", "UTC"),
                    saved["host"], saved["port"],
                    saved["username"], password,
                    saved["remote_path"],
                    nas_mode, **nas_kwargs,
                )
                _log.info(
                    f"Restored NAS backup schedule: {saved['time']} "
                    f"({saved.get('timezone', 'UTC')}) → {saved['host']} mode={nas_mode}"
                )
            except Exception as e:
                _log.warning(f"Could not restore saved NAS schedule: {e}")

        if os.path.exists(RESTORE_SCHEDULE_FILE):
            try:
                with open(RESTORE_SCHEDULE_FILE) as f:
                    saved = json.load(f)
                mode = saved["mode"]
                kwargs = {k: v for k, v in saved.items() if k not in ("time", "timezone", "mode", "user_id")}
                if mode == "range":
                    from datetime import datetime, timezone as _tz
                    kwargs["start_dt"] = datetime.fromisoformat(saved["start_dt"])
                    kwargs["end_dt"] = datetime.fromisoformat(saved["end_dt"])
                apply_restore_schedule(saved["time"], saved.get("timezone", "UTC"), mode, **kwargs)
                _log.info(
                    f"Restored restore schedule: {saved['time']} "
                    f"({saved.get('timezone', 'UTC')}) mode={mode}"
                )
            except Exception as e:
                _log.warning(f"Could not restore saved restore schedule: {e}")

        for imp_file, imp_target in (
            (IMPORT_BACKUP_SCHEDULE_FILE, "backup"),
            (IMPORT_PRODUCTION_SCHEDULE_FILE, "production"),
        ):
            if os.path.exists(imp_file):
                try:
                    with open(imp_file) as f:
                        saved = json.load(f)
                    raw_pw = base64.b64decode(saved["password"])
                    password = decrypt(raw_pw, load_key()).decode()
                    imp_mode = saved.get("mode", "full")
                    _skip = {"time", "timezone", "host", "port", "username", "password",
                             "remote_base_path", "mode", "user_id"}
                    imp_kwargs = {k: v for k, v in saved.items() if k not in _skip}
                    if imp_mode == "range":
                        imp_kwargs["start_dt"] = datetime.fromisoformat(saved["start_dt"])
                        imp_kwargs["end_dt"] = datetime.fromisoformat(saved["end_dt"])
                    apply_import_schedule(
                        saved["time"], saved.get("timezone", "UTC"),
                        imp_target,
                        saved["host"], saved["port"],
                        saved["username"], password,
                        saved["remote_base_path"],
                        imp_mode, **imp_kwargs,
                    )
                    _log.info(
                        f"Restored import schedule ({imp_target}): {saved['time']} "
                        f"({saved.get('timezone', 'UTC')}) mode={imp_mode}"
                    )
                except Exception as e:
                    _log.warning(f"Could not restore saved import schedule ({imp_target}): {e}")

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

    def apply_import_schedule(*_args, **_kwargs) -> None:
        raise RuntimeError("APScheduler not installed. Run: pip install apscheduler")

    def start_backup_scheduler() -> None:
        _log.warning(
            "APScheduler not installed — backup scheduler not started. "
            "Run: pip install apscheduler"
        )

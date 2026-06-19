"""
secure_import.py — External Server/NAS → Verify SHA256 → Decrypt → Insert into DB

Usage:
    python secure_import.py <host> <port> <username> <password> <remote_path> [backup|production]

    backup     → insert into TimescaleDB (default)
    production → insert into Production DB (magistrala)

Requires env var:
    BACKUP_ENCRYPTION_KEY  — same key used during secure_export
"""

import base64
import csv
import gzip
import io
import json
import logging
import sys
from datetime import datetime, timezone

from psycopg2.extras import execute_batch

from db_config import get_source_conn, get_target_conn
from transfer_utils import decrypt, load_key, sftp_connect, sha256_hex

BATCH_SIZE = 10000

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("secure_import")

COLUMNS = [
    "time", "channel", "subtopic", "publisher", "protocol",
    "name", "unit", "value", "string_value", "bool_value",
    "data_value", "sum", "update_time",
]

# TimescaleDB unique constraint: (time, publisher, subtopic, name)
_INSERT_BACKUP = """
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

# Magistrala unique constraint: (time, publisher, subtopic, name)
_INSERT_PRODUCTION = """
    INSERT INTO messages (
        time, channel, subtopic, publisher, protocol,
        name, unit, value, string_value, bool_value,
        data_value, sum, update_time
    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (time, publisher, subtopic, name) DO NOTHING
"""


def _parse_for_source(row: dict) -> tuple:
    """CSV row dict → tuple for Production DB. update_time stays as epoch int (BIGINT)."""
    def s(k): return row[k] if row[k] != "" else None
    def i(k): return int(float(row[k])) if row[k] != "" else None  # handles '0.0', '1700000000.0'
    def f(k): return float(row[k]) if row[k] != "" else None
    def b(k):
        v = row[k]
        if v == "":
            return None
        return v == "1" or v.lower() == "true"
    def byt(k):
        v = row[k]
        return base64.b64decode(v) if v != "" else None

    return (
        i("time"), s("channel"), row["subtopic"] or "", s("publisher"), s("protocol"),
        s("name"), s("unit"), f("value"), s("string_value"), b("bool_value"),
        byt("data_value"), f("sum"), i("update_time"),
    )


def _parse_for_target(row: dict) -> tuple:
    """CSV row dict → tuple for TimescaleDB. update_time as TIMESTAMP (datetime)."""
    base = list(_parse_for_source(row))
    epoch = base[12]
    base[12] = datetime.fromtimestamp(epoch, timezone.utc) if epoch is not None else datetime.now(timezone.utc)
    return tuple(base)


def find_latest_export(sftp, remote_base_path: str) -> str:
    """Return the full path of the most recent export_* subfolder under remote_base_path."""
    entries = sftp.listdir_attr(remote_base_path)
    folders = sorted(
        [e.filename for e in entries if e.filename.startswith("export_")],
        reverse=True,
    )
    if not folders:
        raise FileNotFoundError(f"No export_* folders found under {remote_base_path}")
    return f"{remote_base_path.rstrip('/')}/{folders[0]}"


def _get_row_epoch(row_tuple) -> int:
    """Extract update_time as epoch int from a parsed row tuple (index 12)."""
    val = row_tuple[12]
    if val is None:
        return None
    if isinstance(val, datetime):
        return int(val.timestamp())
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _decrypt_and_parse(encrypted: bytes, key: bytes, row_parser) -> list:
    plaintext = gzip.decompress(decrypt(encrypted, key))
    reader = csv.DictReader(io.StringIO(plaintext.decode("utf-8")))
    return [row_parser(row) for row in reader]


def secure_import(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_path: str,
    target: str = "backup",
    limit: int = None,
    hours: int = None,
    start_dt=None,
    end_dt=None,
) -> dict:
    """
    Download encrypted batch files from remote_path via SFTP, verify each batch's
    SHA256 checksum, decrypt with AES-256-GCM, and insert into the target DB.

    target   : "backup"     → TimescaleDB (backup DB)
               "production" → Magistrala (production DB)
    limit    : hard cap on total rows inserted
    hours    : only import rows with update_time in the last N hours
    start_dt / end_dt : only import rows with update_time in this UTC range
    """
    if target not in ("backup", "production"):
        raise ValueError("target must be 'backup' or 'production'")

    key = load_key()
    started = datetime.now(timezone.utc)

    # Precompute time filter bounds (epoch seconds)
    hours_cutoff = int(started.timestamp()) - hours * 3600 if hours is not None else None
    start_epoch = int(start_dt.timestamp()) if start_dt is not None else None
    end_epoch = int(end_dt.timestamp()) if end_dt is not None else None
    use_time_filter = hours_cutoff is not None or start_epoch is not None

    conn = get_target_conn() if target == "backup" else get_source_conn()
    row_parser = _parse_for_target if target == "backup" else _parse_for_source
    insert_sql = _INSERT_BACKUP if target == "backup" else _INSERT_PRODUCTION

    cur = conn.cursor()
    ssh, sftp = sftp_connect(host, port, username, password)

    try:
        with sftp.open(f"{remote_path}/manifest.json", "r") as f:
            manifest = json.load(f)

        logger.info(
            f"Manifest loaded: {manifest['total_rows']} rows, "
            f"{manifest['total_batches']} batches → target={target}"
        )

        total_verified = 0
        total_inserted = 0

        for entry in manifest["batches"]:
            # Stop when limit reached
            if limit is not None and total_inserted >= limit:
                break

            batch_file = entry["file"]
            expected_checksum = entry["checksum"]
            expected_rows = entry["rows"]

            # Download
            with sftp.open(f"{remote_path}/{batch_file}", "rb") as f:
                encrypted = f.read()

            # Verify SHA256 integrity before decrypting
            actual_checksum = sha256_hex(encrypted)
            if actual_checksum != expected_checksum:
                raise ValueError(
                    f"SHA256 mismatch on {batch_file}: "
                    f"expected {expected_checksum}, got {actual_checksum}"
                )

            total_verified += 1
            logger.info(f"✓ {batch_file} integrity OK")

            # Decrypt and deserialize
            rows = _decrypt_and_parse(encrypted, key, row_parser)

            if len(rows) != expected_rows:
                logger.warning(
                    f"Row count mismatch in {batch_file}: expected {expected_rows}, got {len(rows)}"
                )

            # Apply time filter (hours / range)
            if use_time_filter:
                filtered = []
                for r in rows:
                    ep = _get_row_epoch(r)
                    if ep is None:
                        filtered.append(r)
                        continue
                    if hours_cutoff is not None and ep <= hours_cutoff:
                        continue
                    if start_epoch is not None and not (start_epoch <= ep <= end_epoch):
                        continue
                    filtered.append(r)
                rows = filtered

            # Apply row limit cap
            if limit is not None:
                rows = rows[:limit - total_inserted]

            # Insert
            for i in range(0, len(rows), BATCH_SIZE):
                execute_batch(cur, insert_sql, rows[i : i + BATCH_SIZE])
                conn.commit()

            total_inserted += len(rows)
            logger.info(f"Batch {entry['index']} inserted — {len(rows)} rows")

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        logger.info(f"✅ Secure import done: {total_inserted} rows inserted, {duration:.2f}s")

        return {
            "status": "SUCCESS",
            "target": target,
            "batches_verified": total_verified,
            "rows_inserted": total_inserted,
            "duration_seconds": round(duration, 2),
        }

    except Exception:
        logger.exception("❌ Secure import failed")
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
        sftp.close()
        ssh.close()


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: secure_import.py <host> <port> <username> <password> <remote_path> [backup|production]")
        sys.exit(1)
    tgt = sys.argv[6] if len(sys.argv) > 6 else "backup"
    print(secure_import(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], tgt))

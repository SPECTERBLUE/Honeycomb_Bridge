"""
secure_export.py — Production DB → AES-256-GCM encrypt → SHA256 checksum → SFTP → External Server/NAS

Usage:
    python secure_export.py <host> <port> <username> <password> <remote_path>

Requires env var:
    BACKUP_ENCRYPTION_KEY  — 32 bytes as 64-char hex or base64
"""

import base64
import csv
import gzip
import io
import json
import logging
import sys
from datetime import datetime, timezone

from db_config import get_source_conn
from transfer_utils import encrypt, load_key, sftp_connect, sftp_ensure_dir, sha256_hex

BATCH_SIZE = 10000

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("secure_export")

COLUMNS = [
    "time", "channel", "subtopic", "publisher", "protocol",
    "name", "unit", "value", "string_value", "bool_value",
    "data_value", "sum", "update_time",
]


def _serialize(v) -> str:
    """Convert a DB value to a CSV-safe string."""
    if v is None:
        return ""
    if isinstance(v, (bytes, memoryview)):
        return base64.b64encode(bytes(v)).decode("ascii")
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def _rows_to_csv(rows: list) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLUMNS)
    for row in rows:
        w.writerow([_serialize(v) for v in row])
    return buf.getvalue().encode("utf-8")


def secure_export(host: str, port: int, username: str, password: str, remote_path: str) -> dict:
    """
    Extract all messages from Production DB (magistrala), encrypt each batch of 10000
    rows with AES-256-GCM, generate a SHA256 checksum per batch, and SFTP the encrypted
    files plus a manifest.json to remote_path on the target server.
    """
    key = load_key()
    started = datetime.now(timezone.utc)

    # Each export gets its own timestamped subfolder so multiple exports never overwrite each other
    export_dir = f"{remote_path.rstrip('/')}/export_{started.strftime('%Y%m%d_%H%M%S')}"

    conn = get_source_conn()
    cur = conn.cursor()
    ssh, sftp = sftp_connect(host, port, username, password)

    try:
        sftp_ensure_dir(sftp, export_dir)

        cur.execute(f"SELECT {', '.join(COLUMNS)} FROM messages ORDER BY time")

        manifest = {
            "exported_at": started.isoformat(),
            "total_rows": 0,
            "total_batches": 0,
            "batches": [],
        }

        batch_idx = 0
        total_rows = 0

        while True:
            rows = cur.fetchmany(BATCH_SIZE)
            if not rows:
                break

            csv_bytes = gzip.compress(_rows_to_csv(rows), compresslevel=6)
            encrypted = encrypt(csv_bytes, key)
            checksum = sha256_hex(encrypted)

            batch_file = f"batch_{batch_idx:06d}.enc"
            checksum_file = f"batch_{batch_idx:06d}.sha256"

            with sftp.open(f"{export_dir}/{batch_file}", "wb") as f:
                f.write(encrypted)
            with sftp.open(f"{export_dir}/{checksum_file}", "w") as f:
                f.write(checksum)

            manifest["batches"].append({
                "index": batch_idx,
                "file": batch_file,
                "checksum_file": checksum_file,
                "rows": len(rows),
                "checksum": checksum,
            })

            total_rows += len(rows)
            batch_idx += 1
            logger.info(f"Batch {batch_idx} uploaded — {len(rows)} rows, sha256 {checksum[:16]}…")

        manifest["total_rows"] = total_rows
        manifest["total_batches"] = batch_idx

        with sftp.open(f"{export_dir}/manifest.json", "w") as f:
            f.write(json.dumps(manifest, indent=2))

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        logger.info(f"✅ Secure export done: {total_rows} rows, {batch_idx} batches, {duration:.2f}s")

        return {
            "status": "SUCCESS",
            "total_rows": total_rows,
            "total_batches": batch_idx,
            "duration_seconds": round(duration, 2),
            "export_path": export_dir,  # use this exact path for import/preview
        }

    except Exception:
        logger.exception("❌ Secure export failed")
        raise
    finally:
        cur.close()
        conn.close()
        sftp.close()
        ssh.close()


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: secure_export.py <host> <port> <username> <password> <remote_path>")
        sys.exit(1)
    print(secure_export(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]))

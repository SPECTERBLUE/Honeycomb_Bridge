"""
reverse_sync.py — Target → Source restore
Target: timescaledb (port 5436) — stores update_time as TIMESTAMP
Source: magistrala (port 5433) — stores update_time as epoch BIGINT
Modes:
    python reverse_sync.py              → Full restore
    python reverse_sync.py 24           → Last 24 hours
    python reverse_sync.py --limit 500  → Last 500 records
The update_time TIMESTAMP is converted back to epoch before
inserting into the source DB.
"""
import logging
import sys
from datetime import datetime

from psycopg2.extras import execute_batch

from db_config import get_source_conn, get_target_conn

BATCH_SIZE = 10000
FETCH_SIZE = 10000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("reverse_sync")


def to_epoch(dt):
    """Convert a datetime/TIMESTAMP to epoch seconds. Returns None for NULL."""
    if dt is None:
        return None
    return dt.timestamp()


# ── CLI arg parsing ─────────────────────
LIMIT = None
if "--limit" in sys.argv:
    idx = sys.argv.index("--limit")
    if idx + 1 < len(sys.argv):
        LIMIT = int(sys.argv[idx + 1])


def restore_messages(hours=None):
    start_time = datetime.now()
    total_fetched = 0
    total_inserted = 0

    if LIMIT:
        mode = f"LAST {LIMIT} RECORDS"
    else:
        mode = "FULL (SAFE)" if hours is None else f"LAST {hours} HOURS"

    logger.info(f"Reverse sync started ({mode}) at {start_time}")

    src_conn = get_source_conn()
    tgt_conn = get_target_conn()
    src_cur = src_conn.cursor()
    tgt_cur = tgt_conn.cursor(name="target_cursor")

    try:
        # ── Build target query ──────────────────────────────
        columns = """
            time, channel, subtopic, publisher, protocol,
            name, unit, value, string_value, bool_value,
            data_value, sum, update_time
        """
        if hours is None:
            if LIMIT:
                tgt_query = f"""
                    SELECT * FROM (
                        SELECT {columns}
                        FROM messages
                        ORDER BY time DESC
                        LIMIT %s
                    ) t
                    ORDER BY time
                """
                tgt_cur.execute(tgt_query, (LIMIT,))
            else:
                tgt_query = f"""
                    SELECT {columns}
                    FROM messages
                    ORDER BY time
                """
                tgt_cur.execute(tgt_query)
        else:
            logger.info(f"Restoring last {hours} hours based on update_time")
            tgt_query = f"""
                SELECT {columns}
                FROM messages
                WHERE update_time >= NOW() - (%s * INTERVAL '1 hour')
                ORDER BY update_time
            """
            tgt_cur.execute(tgt_query, (hours,))

        buffer = []

        # Source DB expects update_time as epoch (BIGINT). Convert TIMESTAMP → epoch here.
        insert_sql = """
            INSERT INTO messages (
                time, channel, subtopic, publisher, protocol,
                name, unit, value, string_value, bool_value,
                data_value, sum, update_time
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (time, publisher, subtopic, name) DO NOTHING
        """

        # ── Read & insert loop ─────────────────────────────
        while True:
            rows = tgt_cur.fetchmany(FETCH_SIZE)
            if not rows:
                break
            total_fetched += len(rows)
            for r in rows:
                row = list(r)
                row[-1] = to_epoch(row[-1])
                buffer.append(tuple(row))

            while len(buffer) >= BATCH_SIZE:
                batch = buffer[:BATCH_SIZE]
                execute_batch(src_cur, insert_sql, batch)
                src_conn.commit()
                total_inserted += len(batch)
                buffer = buffer[BATCH_SIZE:]
                logger.info(f"Processed {total_fetched} fetched, {total_inserted} inserted so far...")

        # Flush remaining rows
        if buffer:
            execute_batch(src_cur, insert_sql, buffer)
            src_conn.commit()
            total_inserted += len(buffer)

        # ── Summary ────────────────────────────────────────
        duration = (datetime.now() - start_time).total_seconds()
        logger.info("Reverse Sync Summary")
        logger.info(f"  Mode             : {mode}")
        logger.info(f"  Records fetched  : {total_fetched}")
        logger.info(f"  Records inserted : {total_inserted}")
        logger.info(f"  Duration         : {duration:.2f}s")

    except Exception as e:
        logger.exception(f"Reverse sync FAILED: {e}")
        src_conn.rollback()
        raise

    finally:
        src_cur.close()
        tgt_cur.close()
        src_conn.close()
        tgt_conn.close()


# ── Entry point ─────────────────────────
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1].isdigit():
        restore_messages(int(sys.argv[1]))
    else:
        restore_messages()


import logging
from datetime import datetime, timezone
from psycopg2.extras import execute_batch
from db_config import get_source_conn, get_target_conn

BATCH_SIZE = 10000

# ── Logger Setup ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("sync")


def sync_messages():
    start_time = datetime.now(timezone.utc)
    logger.info(f"🚀 Sync started at: {start_time}")

    src_conn = get_source_conn()
    tgt_conn = get_target_conn()

    src_cur_debug = src_conn.cursor()                  # regular cursor for debug/watermark queries
    src_cur = src_conn.cursor(name="source_cursor")    # named cursor for main data fetch (streams rows)
    tgt_cur = tgt_conn.cursor()

    try:
        # ── Check backup enabled ────────────────────────────
        logger.info("Checking backup_control flag...")
        tgt_cur.execute("SELECT enabled FROM backup_control WHERE id = TRUE")
        row = tgt_cur.fetchone()

        if not row or row[0] is not True:
            logger.warning("Backup disabled. Exiting.")
            return

        logger.info("Backup is ENABLED")

        # ── Get watermark ───────────────────────────────────
        logger.info("Fetching last_message_time (watermark)...")
        tgt_cur.execute("SELECT last_message_time FROM backup_metadata WHERE id = TRUE")
        last_sync = tgt_cur.fetchone()[0]

        if last_sync:
            if last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=timezone.utc)
            else:
                last_sync = last_sync.astimezone(timezone.utc)
            last_sync_epoch = int(last_sync.timestamp())
        else:
            last_sync_epoch = None

        logger.info(f"Watermark (timestamp): {last_sync}")
        logger.info(f"Watermark (epoch): {last_sync_epoch}")

        # ── Debug: Source min/max ───────────────────────────
        logger.info("Checking source DB range...")
        src_cur_debug.execute("""
            SELECT
                MIN(COALESCE(NULLIF(update_time, 0), time)),
                MAX(COALESCE(NULLIF(update_time, 0), time))
            FROM messages
        """)
        min_epoch, max_epoch = src_cur_debug.fetchone()

        logger.info(f"Source MIN epoch: {min_epoch}")
        logger.info(f"Source MAX epoch: {max_epoch}")

        if min_epoch:
            logger.info(f"Source MIN time: {datetime.fromtimestamp(min_epoch, timezone.utc)}")
        if max_epoch:
            logger.info(f"Source MAX time: {datetime.fromtimestamp(max_epoch, timezone.utc)}")

        # ── Fetch new rows ───────────────────────────────────
        logger.info("Fetching rows from source...")

        if last_sync_epoch:
            logger.info("Running incremental query...")
            logger.info(f"Query filter: > {last_sync_epoch}")

            src_cur.execute(
                """
                SELECT
                    time,
                    channel,
                    subtopic,
                    publisher,
                    protocol,
                    name,
                    unit,
                    value,
                    string_value,
                    bool_value,
                    data_value,
                    sum,
                    COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                FROM messages
                WHERE COALESCE(NULLIF(update_time, 0), time) > %s
                ORDER BY update_time_epoch
                """,
                (last_sync_epoch,),
            )
        else:
            logger.info("Running FULL sync (no watermark)...")

            src_cur.execute(
                """
                SELECT
                    time,
                    channel,
                    subtopic,
                    publisher,
                    protocol,
                    name,
                    unit,
                    value,
                    string_value,
                    bool_value,
                    data_value,
                    sum,
                    COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                FROM messages
                ORDER BY update_time_epoch
                """
            )

        insert_sql = """
            INSERT INTO messages (
                time, channel, subtopic, publisher, protocol,
                name, unit, value, string_value, bool_value,
                data_value, sum, update_time
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (time, channel, name) DO UPDATE SET
                subtopic     = EXCLUDED.subtopic,
                publisher    = EXCLUDED.publisher,
                protocol     = EXCLUDED.protocol,
                unit         = EXCLUDED.unit,
                value        = EXCLUDED.value,
                string_value = EXCLUDED.string_value,
                bool_value   = EXCLUDED.bool_value,
                data_value   = EXCLUDED.data_value,
                sum          = EXCLUDED.sum,
                update_time  = EXCLUDED.update_time
        """

        inserted = 0
        total = 0
        latest_epoch = last_sync_epoch

        # ── Stream and process batches ───────────────────────
        while True:
            batch = src_cur.fetchmany(BATCH_SIZE)
            if not batch:
                break

            logger.info(f"Processing batch of {len(batch)} rows (total so far: {total})")

            processed_batch = []
            for row in batch:
                epoch_val = row[-1]
                ts_val = datetime.fromtimestamp(epoch_val, timezone.utc) if epoch_val is not None else datetime.now(timezone.utc)
                processed_batch.append(tuple(list(row[:-1]) + [ts_val]))

            execute_batch(tgt_cur, insert_sql, processed_batch)
            tgt_conn.commit()

            inserted += len(processed_batch)
            total += len(batch)

            batch_latest = max(row[-1] for row in batch)
            if latest_epoch is None or batch_latest > latest_epoch:
                latest_epoch = batch_latest

            logger.info(f"Batch done. Current watermark: {latest_epoch}")

        # ── No data case ─────────────────────────────────────
        if total == 0:
            logger.warning("No new rows found.")

            tgt_cur.execute(
                """
                UPDATE backup_metadata
                SET last_synced_time = %s
                WHERE id = TRUE
                """,
                (datetime.now(timezone.utc),),
            )
            tgt_conn.commit()

            logger.info("Updated last_synced_time only.")
            return

        # ── Update metadata ──────────────────────────────────
        latest_time_ts = datetime.fromtimestamp(latest_epoch, timezone.utc)

        logger.info(f"Final watermark to store: {latest_time_ts}")

        tgt_cur.execute(
            """
            UPDATE backup_metadata
            SET last_synced_time = %s,
                last_message_time = %s
            WHERE id = TRUE
            """,
            (datetime.now(timezone.utc), latest_time_ts),
        )
        tgt_conn.commit()

        logger.info("Metadata updated successfully.")

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        logger.info("✅ Sync completed")
        logger.info(f"Rows processed: {total}")
        logger.info(f"Rows upserted: {inserted}")
        logger.info(f"Duration: {duration:.2f}s")

    except Exception:
        logger.exception("❌ Sync FAILED")
        tgt_conn.rollback()
        raise

    finally:
        src_cur_debug.close()
        src_cur.close()
        tgt_cur.close()
        src_conn.close()
        tgt_conn.close()
        logger.info("Connections closed.")


if __name__ == "__main__":
    sync_messages()
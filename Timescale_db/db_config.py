"""
db_config.py — Centralized database connection helpers.

Credentials are read from environment variables with safe defaults for local dev.

Set these in your environment or .env for production:
    SOURCE_DB_HOST, SOURCE_DB_PORT, SOURCE_DB_NAME, SOURCE_DB_USER, SOURCE_DB_PASSWORD
    TARGET_DB_HOST, TARGET_DB_PORT, TARGET_DB_NAME, TARGET_DB_USER, TARGET_DB_PASSWORD
"""

import os

import psycopg2

APP_DB_URL = os.environ.get("DATABASE_URL", "")

# ── Source DB (magistrala) ──────────────────────────────
SOURCE_DB = {
    "host":     os.environ.get("SOURCE_DB_HOST",     "localhost"),
    "port":     int(os.environ.get("SOURCE_DB_PORT", "5433")),
    "dbname":   os.environ.get("SOURCE_DB_NAME",     "magistrala"),
    "user":     os.environ.get("SOURCE_DB_USER",     "magistrala"),
    "password": os.environ.get("SOURCE_DB_PASSWORD", "magistrala"),
}

# ── Target DB (timescaledb) ─────────────────────────────
TARGET_DB = {
    "host":     os.environ.get("TARGET_DB_HOST",     "localhost"),
    "port":     int(os.environ.get("TARGET_DB_PORT", "5436")),
    "dbname":   os.environ.get("TARGET_DB_NAME",     "timeseries_db"),
    "user":     os.environ.get("TARGET_DB_USER",     "ts_user"),
    "password": os.environ.get("TARGET_DB_PASSWORD", "ts_password"),
}


def get_source_conn():
    """Return a new connection to the source (magistrala) DB."""
    return psycopg2.connect(**SOURCE_DB)


def get_target_conn():
    """Return a new connection to the target (timescaledb) DB."""
    return psycopg2.connect(**TARGET_DB)

-- Enable TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ==============================
-- Messages table
-- ==============================
CREATE TABLE IF NOT EXISTS messages (
    time            BIGINT NOT NULL,
    channel         UUID NOT NULL,
    subtopic        VARCHAR,
    publisher       UUID,
    protocol        TEXT,
    name            VARCHAR NOT NULL,
    unit            TEXT,
    value           DOUBLE PRECISION,
    string_value    TEXT,
    bool_value      BOOLEAN,
    data_value      BYTEA,
    sum             DOUBLE PRECISION,

    -- Tracks when row was written into backup DB
    update_time     TIMESTAMP NOT NULL DEFAULT now()
);

-- Convert to hypertable
SELECT create_hypertable(
    'messages',
    'time',
    if_not_exists => TRUE
);

-- ==============================
-- Indexes
-- ==============================

-- Time queries
CREATE INDEX IF NOT EXISTS idx_messages_time_desc
ON messages (time DESC);

-- Channel + time queries
CREATE INDEX IF NOT EXISTS idx_messages_channel_time
ON messages (channel, time DESC);

-- Incremental sync optimization
CREATE INDEX IF NOT EXISTS idx_messages_update_time
ON messages (update_time);

-- Prevent duplicate sensor readings — matches production PK (time, publisher, subtopic, name)
CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages
ON messages (time, publisher, subtopic, name);

-- ==============================
-- Backup control
-- ==============================
CREATE TABLE IF NOT EXISTS backup_control (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP DEFAULT now()
);

INSERT INTO backup_control (id, enabled)
VALUES (TRUE, TRUE)
ON CONFLICT (id) DO NOTHING;

-- ==============================
-- Backup metadata
-- ==============================
CREATE TABLE IF NOT EXISTS backup_metadata (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,

    -- Actual time sync last executed
    last_synced_time TIMESTAMP,

    -- Watermark used for incremental sync
    last_message_time TIMESTAMP
);

-- Initialize metadata
INSERT INTO backup_metadata (
    id,
    last_synced_time,
    last_message_time
)
VALUES (
    TRUE,
    '1970-01-01 00:00:00',
    '1970-01-01 00:00:00'
)
ON CONFLICT (id) DO NOTHING;
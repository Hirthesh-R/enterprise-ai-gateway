-- Enterprise AI Gateway — MySQL 8 schema (SQLite tables are created automatically by SQLAlchemy).
-- Raw API keys and raw prompts are NEVER stored: only HMAC-SHA256 hashes, masked values and redacted previews.
CREATE DATABASE IF NOT EXISTS gateway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE gateway;

CREATE TABLE IF NOT EXISTS api_keys (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    key_hash      CHAR(64)     NOT NULL UNIQUE,
    key_name      VARCHAR(100) NOT NULL,
    masked_key    VARCHAR(64)  NOT NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'active',
    rate_limit    INT          NOT NULL DEFAULT 100,
    created_at    DATETIME(6)  NOT NULL,
    last_used_at  DATETIME(6)  NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id     VARCHAR(40)  NOT NULL UNIQUE,
    timestamp          DATETIME(6)  NOT NULL,
    api_key_hash       CHAR(64)     NOT NULL,
    masked_api_key     VARCHAR(64)  NOT NULL,
    target_model       VARCHAR(32)  NOT NULL,
    input_tokens       INT          NOT NULL DEFAULT 0,
    output_tokens      INT          NOT NULL DEFAULT 0,
    total_tokens       INT          NOT NULL DEFAULT 0,
    processing_time_ms DOUBLE       NOT NULL DEFAULT 0,
    llm_latency_ms     DOUBLE       NOT NULL DEFAULT 0,
    status             VARCHAR(20)  NOT NULL,
    http_status        INT          NOT NULL,
    pii_detected       BOOLEAN      NOT NULL DEFAULT FALSE,
    pii_redacted       BOOLEAN      NOT NULL DEFAULT FALSE,
    redaction_count    INT          NOT NULL DEFAULT 0,
    pii_types          VARCHAR(200) NOT NULL DEFAULT '',
    injection_detected BOOLEAN      NOT NULL DEFAULT FALSE,
    threat_type        VARCHAR(48)  NULL,
    risk_level         VARCHAR(10)  NULL,
    masked_ip          VARCHAR(64)  NOT NULL,
    prompt_preview     TEXT         NOT NULL,  -- always PII-redacted
    INDEX ix_transactions_timestamp (timestamp),
    INDEX ix_transactions_status (status),
    INDEX ix_transactions_model (target_model),
    INDEX ix_transactions_threat (threat_type)
);

CREATE TABLE IF NOT EXISTS threat_events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id  VARCHAR(40)  NOT NULL,
    timestamp       DATETIME(6)  NOT NULL,
    threat_type     VARCHAR(48)  NOT NULL,
    risk_level      VARCHAR(10)  NOT NULL,
    action          VARCHAR(20)  NOT NULL,  -- BLOCKED | THROTTLED | REJECTED | MONITORED
    masked_ip       VARCHAR(64)  NOT NULL,
    masked_api_key  VARCHAR(64)  NOT NULL,
    matched_rules   VARCHAR(500) NOT NULL DEFAULT '',
    INDEX ix_threat_events_timestamp (timestamp),
    INDEX ix_threat_events_txn (transaction_id)
);

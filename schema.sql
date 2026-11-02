-- Schrock Secret Santa SQLite schema

CREATE TABLE IF NOT EXISTS participants (
    name     TEXT PRIMARY KEY,
    pin_hash TEXT,                       -- null until first login
    giftee   TEXT,
    wishlist TEXT NOT NULL DEFAULT ''    -- default empty string
);

CREATE TABLE IF NOT EXISTS login_attempts (
    name         TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL                    -- Unix timestamp, null = not locked
);

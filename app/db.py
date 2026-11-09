import os
import sqlite3
from contextlib import contextmanager

from . import settings

DB_PATH = os.path.join(settings.DATA_DIR, "ca.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('root','intermediate')),
    parent_id INTEGER REFERENCES cas(id),
    subject TEXT NOT NULL,
    serial TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    path_len INTEGER,
    cert_pem TEXT NOT NULL,
    key_enc TEXT,
    created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id INTEGER NOT NULL REFERENCES cas(id),
    serial TEXT NOT NULL,
    subject TEXT NOT NULL,
    sans TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL,
    source TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    acme_account TEXT,
    revoked_at TEXT,
    revoke_reason TEXT,
    created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS certs_ca ON certs(ca_id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS acme_nonces (nonce TEXT PRIMARY KEY, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS acme_accounts (
    id TEXT PRIMARY KEY, jwk TEXT NOT NULL, thumbprint TEXT NOT NULL UNIQUE,
    contact TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'valid',
    created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS acme_orders (
    id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES acme_accounts(id),
    status TEXT NOT NULL, identifiers TEXT NOT NULL, expires REAL NOT NULL,
    cert_id INTEGER REFERENCES certs(id), error TEXT,
    created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS acme_authzs (
    id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES acme_orders(id),
    id_type TEXT NOT NULL, id_value TEXT NOT NULL, wildcard INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_challenges (
    id TEXT PRIMARY KEY, authz_id TEXT NOT NULL REFERENCES acme_authzs(id),
    type TEXT NOT NULL, token TEXT NOT NULL, status TEXT NOT NULL,
    validated TEXT, error TEXT
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init():
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def get_setting(key, default=None):
    with connect() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key, value):
    with connect() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, None if value is None else str(value)))

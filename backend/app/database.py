import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    email TEXT,
    upn TEXT,
    title TEXT,
    department TEXT,
    manager_dn TEXT,
    phone TEXT,
    location TEXT,
    distinguished_name TEXT NOT NULL,
    status TEXT NOT NULL,
    user_account_control INTEGER,
    pwd_last_set TEXT,
    last_logon_timestamp TEXT,
    synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    distinguished_name TEXT NOT NULL,
    is_critical INTEGER NOT NULL DEFAULT 0,
    synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_groups (
    identity_id TEXT NOT NULL,
    group_dn TEXT NOT NULL,
    group_name TEXT NOT NULL,
    is_critical INTEGER NOT NULL DEFAULT 0,
    synced_at TEXT NOT NULL,
    PRIMARY KEY (identity_id, group_dn)
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    users_synced INTEGER NOT NULL DEFAULT 0,
    groups_synced INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    operator_username TEXT,
    operator_display_name TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_name TEXT,
    target_dn TEXT,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS iam_operators (
    identity_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    permissions_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY (identity_id) REFERENCES identities(id)
);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]

import hashlib
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from app.core.config import DB_PATH


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn():
    conn = _conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS client_registrations (
                id TEXT PRIMARY KEY,
                org_name TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                requested_room_id TEXT,
                requested_room_salt TEXT,
                requested_room_secret_hash TEXT,
                status TEXT NOT NULL,
                requested_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS client_orgs (
                client_id TEXT PRIMARY KEY,
                org_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rooms (
                room_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES client_orgs(client_id)
            );

            CREATE TABLE IF NOT EXISTS room_credentials (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                salt TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                active INTEGER NOT NULL,
                rotated_at TEXT NOT NULL,
                FOREIGN KEY(room_id) REFERENCES rooms(room_id)
            );

            CREATE TABLE IF NOT EXISTS config_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS domain_trust (
                domain TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                note TEXT,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                actor_sub TEXT,
                actor_email TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                payload_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        # Backward-compatible migrations for already-created local DBs.
        for stmt in (
            "ALTER TABLE client_registrations ADD COLUMN requested_room_id TEXT",
            "ALTER TABLE client_registrations ADD COLUMN requested_room_salt TEXT",
            "ALTER TABLE client_registrations ADD COLUMN requested_room_secret_hash TEXT",
        ):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass


def hash_secret(secret: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), bytes.fromhex(salt), 120000).hex()


def issue_room_secret() -> tuple[str, str, str]:
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    return secret, salt, hash_secret(secret, salt)

"""Async SQLite persistence: seen-IP dedup/blacklist, live reservation state,
attempt log and the key-value config store (target, strategy, limits, proxy)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_ips (
    ip TEXT PRIMARY KEY,
    asn INTEGER,
    prefix TEXT,
    as_name TEXT,
    is_target INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    reroll_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reserved (
    service_id TEXT PRIMARY KEY,
    ip TEXT,
    status TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    region TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    asn INTEGER,
    prefix TEXT,
    matched INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SeenRecord:
    ip: str
    asn: int | None
    prefix: str | None
    as_name: str | None
    is_target: bool
    first_seen: str
    last_seen: str
    reroll_count: int

    @property
    def was_seen_before(self) -> bool:
        return self.reroll_count > 0


@dataclass
class ReservedRecord:
    service_id: str
    ip: str | None
    status: str
    reserved_at: str
    region: str | None


class Storage:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        assert self._conn is not None, "Storage.connect() not called"
        return self._conn

    # ---- config (key/value) ----

    async def get_config(self, key: str, default: str | None = None) -> str | None:
        cur = await self.conn.execute("SELECT value FROM config WHERE key = ?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else default

    async def set_config(self, key: str, value: str) -> None:
        await self.conn.execute(
            "INSERT INTO config(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await self.conn.commit()

    async def get_config_json(self, key: str, default=None):
        raw = await self.get_config(key)
        return json.loads(raw) if raw is not None else default

    async def set_config_json(self, key: str, value) -> None:
        await self.set_config(key, json.dumps(value))

    async def seed_config_default(self, key: str, value: str) -> None:
        """Only set if the key doesn't already exist -- used for first-run seeding from .env."""
        existing = await self.get_config(key)
        if existing is None:
            await self.set_config(key, value)

    async def all_config(self) -> dict[str, str]:
        cur = await self.conn.execute("SELECT key, value FROM config")
        rows = await cur.fetchall()
        return {row["key"]: row["value"] for row in rows}

    # ---- seen_ips (dedup / blacklist) ----

    async def get_seen(self, ip: str) -> SeenRecord | None:
        cur = await self.conn.execute("SELECT * FROM seen_ips WHERE ip = ?", (ip,))
        row = await cur.fetchone()
        if row is None:
            return None
        return SeenRecord(
            ip=row["ip"], asn=row["asn"], prefix=row["prefix"], as_name=row["as_name"],
            is_target=bool(row["is_target"]), first_seen=row["first_seen"],
            last_seen=row["last_seen"], reroll_count=row["reroll_count"],
        )

    async def upsert_seen(self, ip: str, asn: int | None, prefix: str | None,
                           as_name: str | None, is_target: bool) -> SeenRecord:
        """Insert or update a seen IP, incrementing reroll_count on repeat sightings.
        Returns the record *after* the update."""
        now = _now()
        existing = await self.get_seen(ip)
        if existing is None:
            await self.conn.execute(
                "INSERT INTO seen_ips(ip, asn, prefix, as_name, is_target, first_seen, "
                "last_seen, reroll_count) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (ip, asn, prefix, as_name, int(is_target), now, now),
            )
        else:
            await self.conn.execute(
                "UPDATE seen_ips SET asn = ?, prefix = ?, as_name = ?, is_target = ?, "
                "last_seen = ?, reroll_count = reroll_count + 1 WHERE ip = ?",
                (asn, prefix, as_name, int(is_target), now, ip),
            )
        await self.conn.commit()
        return await self.get_seen(ip)  # type: ignore[return-value]

    async def seen_stats(self) -> dict:
        cur = await self.conn.execute(
            "SELECT COUNT(*) AS unique_count, "
            "SUM(reroll_count) AS reroll_total, "
            "SUM(is_target) AS target_count FROM seen_ips"
        )
        row = await cur.fetchone()
        return {
            "unique": row["unique_count"] or 0,
            "rerolls": row["reroll_total"] or 0,
            "targets": row["target_count"] or 0,
        }

    # ---- reserved (live state) ----

    async def add_reserved(self, service_id: str, ip: str | None, status: str, region: str | None) -> None:
        await self.conn.execute(
            "INSERT INTO reserved(service_id, ip, status, reserved_at, region) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(service_id) DO UPDATE SET ip = excluded.ip, status = excluded.status",
            (service_id, ip, status, _now(), region),
        )
        await self.conn.commit()

    async def set_reserved_status(self, service_id: str, status: str) -> None:
        await self.conn.execute("UPDATE reserved SET status = ? WHERE service_id = ?", (status, service_id))
        await self.conn.commit()

    async def remove_reserved(self, service_id: str) -> None:
        await self.conn.execute("DELETE FROM reserved WHERE service_id = ?", (service_id,))
        await self.conn.commit()

    async def get_reserved(self, service_id: str) -> ReservedRecord | None:
        cur = await self.conn.execute("SELECT * FROM reserved WHERE service_id = ?", (service_id,))
        row = await cur.fetchone()
        if row is None:
            return None
        return ReservedRecord(row["service_id"], row["ip"], row["status"], row["reserved_at"], row["region"])

    async def list_reserved(self, status: str | None = None) -> list[ReservedRecord]:
        if status is None:
            cur = await self.conn.execute("SELECT * FROM reserved ORDER BY reserved_at ASC")
        else:
            cur = await self.conn.execute(
                "SELECT * FROM reserved WHERE status = ? ORDER BY reserved_at ASC", (status,)
            )
        rows = await cur.fetchall()
        return [
            ReservedRecord(row["service_id"], row["ip"], row["status"], row["reserved_at"], row["region"])
            for row in rows
        ]

    async def count_reserved(self) -> int:
        cur = await self.conn.execute("SELECT COUNT(*) AS c FROM reserved")
        row = await cur.fetchone()
        return row["c"]

    # ---- attempts (analytics / calibration log) ----

    async def log_attempt(self, ip: str, asn: int | None, prefix: str | None, matched: bool) -> None:
        await self.conn.execute(
            "INSERT INTO attempts(ts, ip, asn, prefix, matched) VALUES (?, ?, ?, ?, ?)",
            (_now(), ip, asn, prefix, int(matched)),
        )
        await self.conn.commit()

    async def count_attempts(self) -> int:
        cur = await self.conn.execute("SELECT COUNT(*) AS c FROM attempts")
        row = await cur.fetchone()
        return row["c"]

    async def recent_attempts(self, n: int = 20) -> list[aiosqlite.Row]:
        cur = await self.conn.execute("SELECT * FROM attempts ORDER BY id DESC LIMIT ?", (n,))
        return await cur.fetchall()

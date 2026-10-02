import json
import sqlite3
from datetime import datetime, timezone

from . import rules
from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS protection_periods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stable_key TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    frequency_start_mhz REAL NOT NULL,
                    frequency_end_mhz REAL NOT NULL,
                    start_at TEXT NOT NULL,
                    end_at TEXT NOT NULL,
                    region TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_key TEXT NOT NULL UNIQUE,
                    item_id INTEGER,
                    action TEXT,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
        finally:
            conn.close()

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _build_item(self, conn, row):
        item = self._row_to_item(row)
        sources = []
        for srow in conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item["id"],)).fetchall():
            source = dict(srow)
            source["payload"] = json.loads(source["payload"])
            sources.append(source)
        item["sources"] = sources
        audits = []
        for arow in conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item["id"],)).fetchall():
            audit = dict(arow)
            audit["payload"] = json.loads(audit["payload"])
            audits.append(audit)
        item["audit"] = audits
        item["assessment"] = rules.assess(item["payload"])
        return item

    def _check_idempotency(self, conn, request_key):
        row = conn.execute("SELECT result FROM idempotency_keys WHERE request_key=?", (request_key,)).fetchone()
        if row is not None:
            return json.loads(row["result"])
        return None

    def _store_idempotency(self, conn, request_key, item_id, action, result):
        conn.execute(
            "INSERT INTO idempotency_keys(request_key,item_id,action,result,created_at) VALUES(?,?,?,?,?)",
            (request_key, item_id, action, canonical_json(result), now_iso()),
        )

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else "GENESIS"

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        previous = self._last_hash(conn, item_id)
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": now_iso(),
        }
        event_hash = audit_hash(previous, event)
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), previous, event_hash, event["created_at"]),
        )

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            request_key = None
            if request_id:
                request_key = "item:create:%s" % request_id
                cached = self._check_idempotency(conn, request_key)
                if cached is not None:
                    return cached
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_item", "同一业务实体已经存在")
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            item = self._build_item(conn, conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
            if request_key:
                self._store_idempotency(conn, request_key, item_id, "create", item)
            conn.execute("COMMIT")
            return item
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._build_item(conn, row)
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            request_key = None
            if request_id:
                request_key = "action:%s:%s" % (item_id, request_id)
                cached = self._check_idempotency(conn, request_key)
                if cached is not None:
                    return cached
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            item = self._build_item(conn, conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
            if request_key:
                self._store_idempotency(conn, request_key, item_id, action, item)
            conn.execute("COMMIT")
            return item
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def list_actions(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM actions WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items(), "protection_periods": self.list_protection_periods()}
        finally:
            conn.close()

    def _row_to_protection_period(self, row):
        if row is None:
            return None
        return dict(row)

    def create_protection_period(self, stable_key, payload, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            request_key = None
            if request_id:
                request_key = "protection_period:create:%s" % request_id
                cached = self._check_idempotency(conn, request_key)
                if cached is not None:
                    return cached
            try:
                conn.execute(
                    "INSERT INTO protection_periods(stable_key,name,frequency_start_mhz,frequency_end_mhz,start_at,end_at,region,status,version,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        stable_key,
                        payload["name"],
                        payload["frequency_start_mhz"],
                        payload["frequency_end_mhz"],
                        payload["start_at"],
                        payload["end_at"],
                        payload.get("region"),
                        "active",
                        1,
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_protection_period", "同一保护时段已经存在")
            period_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            period = self._row_to_protection_period(conn.execute("SELECT * FROM protection_periods WHERE id=?", (period_id,)).fetchone())
            if request_key:
                self._store_idempotency(conn, request_key, period_id, "create", period)
            conn.execute("COMMIT")
            return period
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_protection_period(self, period_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM protection_periods WHERE id=?", (period_id,)).fetchone()
            if row is None:
                raise NotFoundError("protection_period_not_found", "保护时段不存在")
            return self._row_to_protection_period(row)
        finally:
            conn.close()

    def list_protection_periods(self):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM protection_periods ORDER BY id DESC").fetchall()
            return [self._row_to_protection_period(row) for row in rows]
        finally:
            conn.close()

    def update_protection_period(self, period_id, new_payload, actor, role, expected_version=None, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            request_key = None
            if request_id:
                request_key = "protection_period:update:%s:%s" % (period_id, request_id)
                cached = self._check_idempotency(conn, request_key)
                if cached is not None:
                    return cached
            row = conn.execute("SELECT * FROM protection_periods WHERE id=?", (period_id,)).fetchone()
            if row is None:
                raise NotFoundError("protection_period_not_found", "保护时段不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "保护时段已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE protection_periods SET name=?,frequency_start_mhz=?,frequency_end_mhz=?,start_at=?,end_at=?,region=?,version=?,updated_at=? WHERE id=?",
                (
                    new_payload["name"],
                    new_payload["frequency_start_mhz"],
                    new_payload["frequency_end_mhz"],
                    new_payload["start_at"],
                    new_payload["end_at"],
                    new_payload.get("region"),
                    version,
                    now_iso(),
                    period_id,
                ),
            )
            affected = conn.execute(
                "SELECT id FROM items WHERE entity_type='spectrum_interference' AND status IN ('suspended','coordinating') AND json_extract(payload, '$.suspend_authorization.protection_period_id')=?",
                (period_id,),
            ).fetchall()
            for erow in affected:
                event_id = erow["id"]
                event = conn.execute("SELECT * FROM items WHERE id=?", (event_id,)).fetchone()
                event_payload = json.loads(event["payload"])
                previous_status = event["status"]
                event_payload["suspend_authorization"] = None
                conn.execute(
                    "UPDATE items SET status=?,payload=?,updated_at=? WHERE id=?",
                    (rules.REVIEW_STATUS, canonical_json(event_payload), now_iso(), event_id),
                )
                conn.execute(
                    "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                    (event_id, "protection_period_changed", actor, role, canonical_json({"protection_period_id": period_id, "previous_status": previous_status}), now_iso()),
                )
                self.append_audit(
                    conn,
                    event_id,
                    "protection_period_changed",
                    actor,
                    role,
                    {"protection_period_id": period_id, "previous_status": previous_status, "reason": "coverage_no_longer_matches"},
                )
            period = self._row_to_protection_period(conn.execute("SELECT * FROM protection_periods WHERE id=?", (period_id,)).fetchone())
            if request_key:
                self._store_idempotency(conn, request_key, period_id, "update", period)
            conn.execute("COMMIT")
            return period
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

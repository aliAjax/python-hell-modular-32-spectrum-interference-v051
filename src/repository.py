import json
import sqlite3
from datetime import datetime, timezone

from . import rules
from .audit import audit_hash, canonical_json
from .domain import ConflictError, DomainError, NotFoundError, ServiceResult


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
                    window_id INTEGER,
                    window_version INTEGER,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS protection_windows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, region)
                );
                CREATE TABLE IF NOT EXISTS suspend_authorizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    window_id INTEGER NOT NULL,
                    window_version INTEGER NOT NULL,
                    code TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    invalidated_at TEXT,
                    invalidate_reason TEXT,
                    FOREIGN KEY(item_id) REFERENCES items(id),
                    FOREIGN KEY(window_id) REFERENCES protection_windows(id)
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
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    request_id TEXT PRIMARY KEY,
                    op_key TEXT NOT NULL,
                    response_status INTEGER,
                    response_payload TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(items)")}
            if "window_id" not in columns:
                conn.execute("ALTER TABLE items ADD COLUMN window_id INTEGER")
            if "window_version" not in columns:
                conn.execute("ALTER TABLE items ADD COLUMN window_version INTEGER")
        finally:
            conn.close()

    # ------------------------------------------------------------------ helpers

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _row_to_window(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _load_item(self, conn, item_id):
        row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("item_not_found", "业务实体不存在")
        return self._row_to_item(row)

    def _load_window(self, conn, window_id):
        row = conn.execute("SELECT * FROM protection_windows WHERE id=?", (window_id,)).fetchone()
        if row is None:
            raise NotFoundError("window_not_found", "保护时段不存在")
        return self._row_to_window(row)

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

    def _claim_request(self, conn, request_id, op_key):
        """在 IMMEDIATE 事务内登记请求编号。

        新登记返回 False；重复编号且原请求已完成时返回已存响应；原请求仍在
        处理中或编号被挪作他用时抛出冲突。登记行随事务回滚而清除，因此失败
        的请求可以用同一编号原样重试。
        """
        if not request_id:
            return False
        try:
            conn.execute(
                "INSERT INTO idempotency_records(request_id,op_key,response_status,response_payload,created_at) VALUES(?,?,?,?,?)",
                (request_id, op_key, None, None, now_iso()),
            )
        except sqlite3.IntegrityError:
            row = conn.execute(
                "SELECT * FROM idempotency_records WHERE request_id=?", (request_id,)
            ).fetchone()
            if row["op_key"] != op_key:
                raise ConflictError("request_id_reused", "请求编号已用于其他操作，请更换编号")
            if row["response_payload"] is None:
                raise ConflictError("request_in_progress", "同一编号的请求仍在处理中，请稍后重试")
            return row["response_status"], json.loads(row["response_payload"]), True
        return False

    def _store_response(self, conn, request_id, status, payload):
        if request_id:
            conn.execute(
                "UPDATE idempotency_records SET response_status=?, response_payload=? WHERE request_id=?",
                (status, canonical_json(payload), request_id),
            )

    @staticmethod
    def _replayed(claim):
        return claim is not False

    def _gather_item(self, conn, item):
        rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item["id"],)).fetchall()
        sources = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            sources.append(value)
        audit_rows = conn.execute(
            "SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item["id"],)
        ).fetchall()
        audit = []
        for row in audit_rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            audit.append(value)
        authorizations = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM suspend_authorizations WHERE item_id=? ORDER BY id", (item["id"],)
            ).fetchall()
        ]
        window_row = conn.execute(
            "SELECT * FROM protection_windows WHERE entity_type=? AND region=?",
            (rules.WINDOW_ENTITY_TYPE, item["payload"].get("region")),
        ).fetchone()
        active_window = self._row_to_window(window_row)
        return dict(
            item,
            sources=sources,
            audit=audit,
            authorizations=authorizations,
            assessment=rules.assess(item["payload"]),
            protection={
                "window_id": item.get("window_id"),
                "window_version": item.get("window_version"),
                "active_window": active_window,
                "covered": rules.item_covered_by_window(item["payload"], active_window),
            },
        )

    # ------------------------------------------------------------------ reads

    def get_item(self, item_id):
        conn = self.connect()
        try:
            return self._load_item(conn, item_id)
        finally:
            conn.close()

    def get_item_view(self, item_id):
        conn = self.connect()
        try:
            return self._gather_item(conn, self._load_item(conn, item_id))
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

    def get_window(self, window_id):
        conn = self.connect()
        try:
            return self._load_window(conn, window_id)
        finally:
            conn.close()

    def list_windows(self):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM protection_windows ORDER BY id DESC").fetchall()
            return [self._row_to_window(row) for row in rows]
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

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {
                "counts": counts,
                "items": self.list_items(),
                "protection_windows": self.list_windows(),
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------ writes

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            claim = self._claim_request(conn, request_id, "item:create:%s" % stable_key)
            if self._replayed(claim):
                conn.execute("COMMIT")
                status, body, _ = claim
                return ServiceResult(body, status, replayed=True)
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
            view = self._gather_item(conn, self._load_item(conn, item_id))
            self._store_response(conn, request_id, 201, view)
            conn.execute("COMMIT")
            return ServiceResult(view, 201)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            claim = self._claim_request(
                conn, request_id, "item:%s:source:%s:%s" % (item_id, source_type, external_id)
            )
            if self._replayed(claim):
                conn.execute("COMMIT")
                status, body, _ = claim
                return ServiceResult(body, status, replayed=True)
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
            result = {
                "id": source_id,
                "item_id": item_id,
                "source_type": source_type,
                "external_id": external_id,
                "payload": payload,
                "observed_at": observed_at,
            }
            self._store_response(conn, request_id, 201, result)
            conn.execute("COMMIT")
            return ServiceResult(result, 201)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def apply_action(self, item_id, action, raw_payload, actor, role, expected_version=None, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            claim = self._claim_request(conn, request_id, "item:%s:action:%s" % (item_id, action))
            if self._replayed(claim):
                conn.execute("COMMIT")
                status, body, _ = claim
                return ServiceResult(body, status, replayed=True)

            item = self._load_item(conn, item_id)
            if expected_version is not None and int(expected_version) != int(item["version"]):
                raise ConflictError(
                    "version_conflict",
                    "记录已被其他操作更新，请携带最新状态重做",
                    {"latest": {"id": item_id, "status": item["status"], "version": item["version"]}},
                )

            authorization = None
            if action in ("suspend", "reconfirm"):
                allowed = rules.SUSPEND_FROM if action == "suspend" else rules.RECONFIRM_FROM
                if item["status"] not in allowed:
                    raise DomainError("invalid_state", "当前状态 %s 不允许执行该操作" % item["status"])
                code = rules.authorization_code(raw_payload)
                window_row = conn.execute(
                    "SELECT * FROM protection_windows WHERE entity_type=? AND region=? AND status='active'",
                    (rules.WINDOW_ENTITY_TYPE, item["payload"].get("region")),
                ).fetchone()
                window = self._row_to_window(window_row)
                if window is None:
                    raise DomainError(
                        "no_protection_window", "当前区域没有保护时段，不能停用", 409
                    )
                if not rules.frequency_in_window(item["payload"], window["payload"]):
                    raise ConflictError(
                        "protection_coverage_mismatch",
                        "干扰频段不在保护时段覆盖范围内，不能停用",
                        {"window": {"id": window["id"], "version": window["version"], **window["payload"]}},
                    )
                conn.execute(
                    "INSERT INTO suspend_authorizations(item_id,window_id,window_version,code,status,actor,role,created_at) VALUES(?,?,?,?, 'active',?,?,?)",
                    (
                        item_id,
                        window["id"],
                        window["version"],
                        code,
                        actor,
                        role,
                        now_iso(),
                    ),
                )
                authorization_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
                authorization = {
                    "id": authorization_id,
                    "window_id": window["id"],
                    "window_version": window["version"],
                    "code": code,
                }
            elif action in ("coordinate", "resolve") and item.get("window_id") is not None:
                # 防御性校验：授权已随保护时段调整失效时，结案链路必须停下来
                active = conn.execute(
                    "SELECT COUNT(*) AS total FROM suspend_authorizations "
                    "WHERE item_id=? AND window_id=? AND window_version=? AND status='active'",
                    (item_id, item["window_id"], item["window_version"]),
                ).fetchone()["total"]
                if not active:
                    raise ConflictError(
                        "authorization_invalidated",
                        "停用授权已随保护时段调整失效，请退回复核重新确认",
                        {"latest": {"id": item_id, "status": item["status"], "version": item["version"]}},
                    )

            new_status, new_payload, event_payload = rules.apply_action(
                item, action, raw_payload, actor, role, authorization
            )
            version = int(item["version"]) + 1
            window_id = item.get("window_id")
            window_version = item.get("window_version")
            if authorization is not None:
                window_id = authorization["window_id"]
                window_version = authorization["window_version"]
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,window_id=?,window_version=?,updated_at=? WHERE id=?",
                (
                    new_status,
                    version,
                    canonical_json(new_payload),
                    window_id,
                    window_version,
                    now_iso(),
                    item_id,
                ),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            view = self._gather_item(conn, self._load_item(conn, item_id))
            self._store_response(conn, request_id, 200, view)
            conn.execute("COMMIT")
            return ServiceResult(view, 200)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def create_window(self, payload, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            claim = self._claim_request(
                conn, request_id, "window:create:%s" % payload["region"]
            )
            if self._replayed(claim):
                conn.execute("COMMIT")
                status, body, _ = claim
                return ServiceResult(body, status, replayed=True)
            try:
                conn.execute(
                    "INSERT INTO protection_windows(entity_type,region,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,'active',1,?,?,?,?,?)",
                    (
                        rules.WINDOW_ENTITY_TYPE,
                        payload["region"],
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("window_exists", "该区域已经存在保护时段，请改用时段变更")
            window_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn, None, "window_created", actor, role,
                {"window_id": window_id, "region": payload["region"]},
            )
            window = self._load_window(conn, window_id)
            self._store_response(conn, request_id, 201, window)
            conn.execute("COMMIT")
            return ServiceResult(window, 201)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def adjust_window(self, window_id, payload, expected_version, actor, role, request_id=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            claim = self._claim_request(conn, request_id, "window:%s:adjust" % window_id)
            if self._replayed(claim):
                conn.execute("COMMIT")
                status, body, _ = claim
                return ServiceResult(body, status, replayed=True)

            window = self._load_window(conn, window_id)
            if expected_version is not None and int(expected_version) != int(window["version"]):
                raise ConflictError(
                    "version_conflict",
                    "保护时段已被其他协调员变更，请携带最新状态重做",
                    {"latest": {"id": window_id, "region": window["region"], "version": window["version"]}},
                )

            timestamp = now_iso()
            old_version = int(window["version"])
            new_version = old_version + 1
            conn.execute(
                "UPDATE protection_windows SET version=?,payload=?,updated_at=? WHERE id=?",
                (new_version, canonical_json(payload), timestamp, window_id),
            )

            auth_rows = conn.execute(
                "SELECT * FROM suspend_authorizations WHERE window_id=? AND status='active' ORDER BY id",
                (window_id,),
            ).fetchall()
            invalidated_authorization_ids = []
            affected_item_ids = []
            for row in auth_rows:
                conn.execute(
                    "UPDATE suspend_authorizations SET status='invalidated', invalidated_at=?, "
                    "invalidate_reason='protection_window_adjusted' WHERE id=?",
                    (timestamp, row["id"]),
                )
                invalidated_authorization_ids.append(row["id"])
                item = self._load_item(conn, row["item_id"])
                if item["id"] not in affected_item_ids:
                    affected_item_ids.append(item["id"])
                if item["status"] in rules.TERMINAL_STATUSES:
                    # 已结案/已撤销的事件保持终态，授权仍标记失效
                    continue
                item_payload = item["payload"]
                coverage_matches = rules.frequency_in_window(item_payload, payload)
                item_payload["current_review"] = {
                    "reason": "protection_window_adjusted",
                    "previous_window_version": old_version,
                    "window_version": new_version,
                    "invalidated_authorization_id": row["id"],
                    "coverage_matches": coverage_matches,
                    "actor": actor,
                    "at": timestamp,
                }
                conn.execute(
                    "UPDATE items SET status='review',version=version+1,payload=?,updated_at=? WHERE id=?",
                    (canonical_json(item_payload), timestamp, item["id"]),
                )
                self.append_audit(
                    conn,
                    item["id"],
                    "protection_window_changed",
                    actor,
                    role,
                    {
                        "window_id": window_id,
                        "from_version": old_version,
                        "to_version": new_version,
                        "invalidated_authorization_id": row["id"],
                        "coverage_matches": item_payload["current_review"]["coverage_matches"],
                    },
                )

            self.append_audit(
                conn,
                None,
                "window_adjusted",
                actor,
                role,
                {
                    "window_id": window_id,
                    "region": payload["region"],
                    "from_version": old_version,
                    "to_version": new_version,
                    "affected_item_ids": affected_item_ids,
                    "invalidated_authorization_ids": invalidated_authorization_ids,
                    "start_mhz": payload["start_mhz"],
                    "end_mhz": payload["end_mhz"],
                },
            )
            result = {
                "window": self._load_window(conn, window_id),
                "affected_item_ids": affected_item_ids,
                "invalidated_authorization_ids": invalidated_authorization_ids,
            }
            self._store_response(conn, request_id, 200, result)
            conn.execute("COMMIT")
            return ServiceResult(result, 200)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

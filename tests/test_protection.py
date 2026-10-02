import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError
from src.audit import audit_hash


WINDOW_BASE = {
    "region": "north",
    "start_mhz": 2300.0,
    "end_mhz": 2500.0,
    "starts_at": "2026-09-27T00:00:00+00:00",
    "ends_at": "2026-09-28T00:00:00+00:00",
}


class ProtectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.window = self.service.create_window(
            dict(WINDOW_BASE, label="北区保护"), "coord-1", "coordinator"
        )

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _item(self, frequency=2400.0, bandwidth=10.0, region="north", station="ST-1", detected="2026-09-27T10:00:00+00:00"):
        return self.service.create_item({
            "frequency_mhz": frequency,
            "bandwidth_mhz": bandwidth,
            "station_id": station,
            "region": region,
            "strength_dbm": -45,
            "detected_at": detected,
            "reporter": "monitor-1",
        }, "analyst-1", "analyst")

    def _to_suspended(self, code="REG-1"):
        item = self._item()
        item = self.service.act(item["id"], "assess", {}, "analyst-1", "analyst", item["version"])
        item = self.service.act(item["id"], "locate", {"location": "cell-7", "confidence": 0.9},
                                "field-1", "field_operator", item["version"])
        item = self.service.act(item["id"], "suspend", {"authorization_code": code},
                                "coord-1", "coordinator", item["version"], "north")
        return item

    def test_suspend_requires_matching_window(self):
        item = self._item(frequency=2700.0, station="ST-OUT")  # 频段在保护范围之外
        item = self.service.act(item["id"], "assess", {}, "analyst-1", "analyst", item["version"])
        item = self.service.act(item["id"], "locate", {"location": "x", "confidence": 0.9},
                                "field-1", "field_operator", item["version"])
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "suspend", {"authorization_code": "REG-X"},
                             "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(context.exception.code, "protection_coverage_mismatch")
        # 区域内完全没有保护时段
        item = self._item(frequency=5800.0, region="south", station="ST-S")
        item = self.service.act(item["id"], "assess", {}, "analyst-1", "analyst", item["version"])
        item = self.service.act(item["id"], "locate", {"location": "x", "confidence": 0.9},
                                "field-1", "field_operator", item["version"])
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "suspend", {"authorization_code": "REG-S"},
                             "coord-1", "coordinator", item["version"], "south")
        self.assertEqual(context.exception.code, "no_protection_window")

    def test_window_adjust_invalidates_authorization_and_sends_item_to_review(self):
        item = self._to_suspended("REG-A")
        self.assertEqual(item["status"], "suspended")
        self.assertEqual(item["window_version"], 1)

        result = self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, start_mhz=2350.0, end_mhz=2450.0, label="缩窄"),
            "coord-2", "coordinator", self.window["version"], "north",
        )
        self.assertEqual(result["window"]["version"], 2)
        self.assertEqual(result["affected_item_ids"], [item["id"]])
        self.assertEqual(len(result["invalidated_authorization_ids"]), 1)

        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        self.assertEqual(item["version"], 5)  # assess/locate/suspend 之后又被级联推进一步
        self.assertEqual(item["payload"]["current_review"]["reason"], "protection_window_adjusted")
        auth = next(a for a in item["authorizations"] if a["code"] == "REG-A")
        self.assertEqual(auth["status"], "invalidated")
        self.assertEqual(auth["invalidate_reason"], "protection_window_adjusted")

        # 授权失效后不能直接进入协调/结案，必须重新确认
        with self.assertRaises(DomainError) as blocked:
            self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC"},
                             "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(blocked.exception.code, "authorization_invalidated")

        # 在新的窗口版本上重新确认，授权重新登记且不复活旧记录
        item = self.service.act(item["id"], "reconfirm", {"authorization_code": "REG-B"},
                                "coord-2", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "suspended")
        self.assertEqual(item["window_version"], 2)
        self.assertIsNone(item["payload"].get("current_review"))
        statuses = sorted(a["status"] for a in item["authorizations"])
        self.assertEqual(statuses, ["active", "invalidated"])
        codes = [a["code"] for a in item["authorizations"] if a["status"] == "active"]
        self.assertEqual(codes, ["REG-B"])

    def test_coverage_no_longer_matches_cannot_reconfirm(self):
        item = self._to_suspended()
        # 时段改到完全不覆盖 2400MHz 的范围
        self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, start_mhz=2600.0, end_mhz=2700.0, label="移频"),
            "coord-2", "coordinator", self.window["version"], "north",
        )
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        self.assertFalse(item["payload"]["current_review"]["coverage_matches"])
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "reconfirm", {"authorization_code": "REG-B"},
                             "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(context.exception.code, "protection_coverage_mismatch")
        self.assertEqual(self.service.get_item(item["id"])["status"], "review")

    def test_coordinating_item_is_pulled_back_to_review(self):
        item = self._to_suspended()
        item = self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC-9"},
                                "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "coordinating")
        self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, end_mhz=2480.0, label="微调"),
            "coord-2", "coordinator", self.window["version"], "north",
        )
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        # 旧版本号结案必须被拒绝
        with self.assertRaises(ConflictError) as stale:
            self.service.act(item["id"], "resolve",
                             {"measurement_cleared": True, "evidence": "e"},
                             "coord-1", "coordinator", item["version"] - 1, "north")
        self.assertEqual(stale.exception.code, "version_conflict")

    def test_resolved_item_keeps_terminal_status_but_authorization_invalidates(self):
        item = self._to_suspended()
        item = self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC-9"},
                                "coord-1", "coordinator", item["version"], "north")
        item = self.service.act(item["id"], "resolve",
                                {"measurement_cleared": True, "evidence": "scan"},
                                "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "resolved")
        self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, end_mhz=2490.0, label="微调"),
            "coord-2", "coordinator", self.window["version"], "north",
        )
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "resolved")
        self.assertEqual(item["authorizations"][0]["status"], "invalidated")

    def test_first_write_wins_on_concurrent_resolve(self):
        item = self._to_suspended()
        item = self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC"},
                                "coord-1", "coordinator", item["version"], "north")
        version = item["version"]
        errors = []

        def resolve(coord, code):
            try:
                self.service.act(item["id"], "resolve",
                                 {"measurement_cleared": True, "evidence": code},
                                 coord, "coordinator", version, "north")
            except DomainError as exc:
                errors.append(exc.code)

        threads = [
            threading.Thread(target=resolve, args=("coord-a", "E-A")),
            threading.Thread(target=resolve, args=("coord-b", "E-B")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(errors).count("version_conflict"), 1)
        final = self.service.get_item(item["id"])
        self.assertEqual(final["status"], "resolved")
        self.assertEqual(final["version"], version + 1)

    def test_first_write_wins_on_concurrent_window_adjust(self):
        errors = []

        def adjust(coord, end_mhz):
            try:
                self.service.adjust_window(
                    self.window["id"],
                    dict(WINDOW_BASE, end_mhz=end_mhz, label="x"),
                    coord, "coordinator", 1, "north",
                )
            except DomainError as exc:
                errors.append((coord, exc.code))

        threads = [
            threading.Thread(target=adjust, args=("coord-a", 2495.0)),
            threading.Thread(target=adjust, args=("coord-b", 2475.0)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][1], "version_conflict")
        window = self.service.get_window(self.window["id"])
        self.assertEqual(window["version"], 2)
        # 冲突响应里带最新状态，后到者据此重做
        self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, end_mhz=2460.0, label="基于v2再改"),
            "coord-b", "coordinator", 2, "north",
        )
        self.assertEqual(self.service.get_window(self.window["id"])["version"], 3)

    def test_retry_by_same_request_id_replays_without_duplicate_writes(self):
        # 首次创建授权
        first = self.service.act(self._prep_item(), "suspend", {"authorization_code": "REG-IDEM"},
                                 "coord-1", "coordinator", 3, "north", request_id="REQ-77")
        self.assertFalse(first.replayed)
        # 用同一请求编号重试：即使带了不同（过期）版本号，也必须回放原结果而不是再写一次
        replay = self.service.act(first["id"], "suspend", {"authorization_code": "REG-OTHER"},
                                  "coord-1", "coordinator", 3, "north", request_id="REQ-77")
        self.assertTrue(replay.replayed)
        self.assertEqual(replay["id"], first["id"])
        self.assertEqual(replay["payload"]["suspend_authorization"], "REG-IDEM")
        item = self.service.get_item(first["id"])
        self.assertEqual(len(item["authorizations"]), 1)
        # 审计只记录一次停用
        self.assertEqual([e["event_type"] for e in item["audit"]].count("suspend"), 1)

    def _prep_item(self):
        item = self._item()
        item = self.service.act(item["id"], "assess", {}, "analyst-1", "analyst", item["version"])
        item = self.service.act(item["id"], "locate", {"location": "x", "confidence": 0.9},
                                "field-1", "field_operator", item["version"])
        return item["id"]

    def test_window_adjust_is_idempotent_and_does_not_double_invalidate(self):
        item = self._to_suspended()
        payload = dict(WINDOW_BASE, end_mhz=2488.0, label="幂等调整")
        first = self.service.adjust_window(self.window["id"], payload,
                                           "coord-1", "coordinator", 1, "north", request_id="WIN-9")
        self.assertFalse(first.replayed)
        replay = self.service.adjust_window(self.window["id"], dict(payload),
                                            "coord-1", "coordinator", 1, "north", request_id="WIN-9")
        self.assertTrue(replay.replayed)
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        # 旧授权只失效一次，事件只回退一次（版本号停在 5）
        self.assertEqual(item["version"], 5)
        self.assertEqual(len([a for a in item["authorizations"] if a["status"] == "invalidated"]), 1)

    def test_request_id_cannot_be_reused_for_different_operation(self):
        self._to_suspended()
        self.service.adjust_window(self.window["id"], dict(WINDOW_BASE, end_mhz=2488.0),
                                   "coord-1", "coordinator", 1, "north", request_id="DUP")
        with self.assertRaises(ConflictError) as context:
            self.service.create_window({
                "region": "south", "start_mhz": 100.0, "end_mhz": 200.0,
                "starts_at": WINDOW_BASE["starts_at"], "ends_at": WINDOW_BASE["ends_at"],
            }, "coord-1", "coordinator", request_id="DUP")
        self.assertEqual(context.exception.code, "request_id_reused")

    def test_per_item_audit_chain_stays_intact_through_cascade(self):
        item = self._to_suspended()
        result = self.service.adjust_window(
            self.window["id"],
            dict(WINDOW_BASE, end_mhz=2482.0, label="链校验"),
            "coord-2", "coordinator", self.window["version"], "north",
        )
        item = self.service.get_item(item["id"])
        previous = "GENESIS"
        for event in item["audit"]:
            self.assertEqual(event["previous_hash"], previous)
            body = {
                "item_id": event["item_id"],
                "event_type": event["event_type"],
                "actor": event["actor"],
                "role": event["role"],
                "payload": event["payload"],
                "created_at": event["created_at"],
            }
            self.assertEqual(event["event_hash"], audit_hash(previous, body))
            previous = event["event_hash"]
        self.assertEqual(result["window"]["version"], 2)

    def test_window_creation_is_single_active_per_region_and_role_checked(self):
        with self.assertRaises(ConflictError) as context:
            self.service.create_window(dict(WINDOW_BASE, label="重复"),
                                       "coord-1", "coordinator")
        self.assertEqual(context.exception.code, "window_exists")
        with self.assertRaises(DomainError) as context:
            self.service.create_window({
                "region": "east", "start_mhz": 100.0, "end_mhz": 200.0,
                "starts_at": WINDOW_BASE["starts_at"], "ends_at": WINDOW_BASE["ends_at"],
            }, "analyst-1", "analyst")
        self.assertEqual(context.exception.code, "forbidden")
        with self.assertRaises(DomainError) as context:
            self.service.adjust_window(self.window["id"], dict(WINDOW_BASE, end_mhz=2490.0),
                                       "coord-1", "coordinator", 1, "south")
        self.assertEqual(context.exception.code, "region_mismatch")


if __name__ == "__main__":
    unittest.main()

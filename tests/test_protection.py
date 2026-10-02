import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError


class ProtectionPeriodTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.period_payload = {
            "name": "重大活动保护",
            "frequency_start_mhz": 2400.0,
            "frequency_end_mhz": 2500.0,
            "start_at": "2026-09-27T00:00:00+00:00",
            "end_at": "2026-09-28T00:00:00+00:00",
            "region": "north",
        }

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _create_item(self, frequency=2450.0, detected_at="2026-09-27T10:00:00+00:00", region="north"):
        item = self.service.create_item({
            "frequency_mhz": frequency,
            "bandwidth_mhz": 20.0,
            "station_id": "ST-01",
            "region": region,
            "strength_dbm": -40,
            "detected_at": detected_at,
            "reporter": "monitor-1",
        }, "analyst-1", "analyst")
        item = self.service.act(item["id"], "assess", {}, "analyst-1", "analyst", item["version"])
        item = self.service.act(item["id"], "locate", {"location": "cell-7", "confidence": 0.9}, "field-1", "field_operator", item["version"])
        return item

    def test_create_and_get_protection_period(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        self.assertEqual(period["name"], "重大活动保护")
        self.assertEqual(period["status"], "active")
        self.assertEqual(period["version"], 1)
        fetched = self.service.get_protection_period(period["id"])
        self.assertEqual(fetched["id"], period["id"])
        self.assertEqual(fetched["frequency_start_mhz"], 2400.0)

    def test_suspend_requires_protection_period(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "suspend", {"authorization_code": "REG-X"}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(ctx.exception.code, "protection_period_required")

    def test_suspend_records_authorization_with_coverage(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "suspended")
        auth = item["payload"]["suspend_authorization"]
        self.assertEqual(auth["authorization_code"], "REG-NORTH-1")
        self.assertEqual(auth["protection_period_id"], period["id"])
        self.assertEqual(auth["coverage"]["frequency_start_mhz"], 2400.0)
        self.assertEqual(auth["coverage"]["frequency_end_mhz"], 2500.0)

    def test_suspend_rejects_frequency_outside_band(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item(frequency=2600.0)
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "suspend", {"authorization_code": "REG-X", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(ctx.exception.code, "coverage_mismatch")

    def test_suspend_rejects_time_outside_range(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item(detected_at="2026-09-29T10:00:00+00:00")
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "suspend", {"authorization_code": "REG-X", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(ctx.exception.code, "coverage_mismatch")

    def test_period_change_returns_event_to_review(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "suspended")

        new_payload = dict(self.period_payload)
        new_payload["frequency_end_mhz"] = 2600.0
        period = self.service.update_protection_period(period["id"], "update", new_payload, "coord-1", "coordinator", period["version"], "north")
        self.assertEqual(period["version"], 2)

        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        self.assertIsNone(item["payload"]["suspend_authorization"])
        audit_types = [event["event_type"] for event in item["audit"]]
        self.assertIn("protection_period_changed", audit_types)

    def test_period_change_does_not_affect_resolved_events(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        item = self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC-7"}, "coord-1", "coordinator", item["version"], "north")
        item = self.service.act(item["id"], "resolve", {"measurement_cleared": True, "evidence": "scan-7"}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "resolved")

        new_payload = dict(self.period_payload)
        new_payload["frequency_end_mhz"] = 2600.0
        period = self.service.update_protection_period(period["id"], "update", new_payload, "coord-1", "coordinator", period["version"], "north")

        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "resolved")

    def test_reconfirm_after_review(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")

        new_payload = dict(self.period_payload)
        new_payload["frequency_end_mhz"] = 2600.0
        period = self.service.update_protection_period(period["id"], "update", new_payload, "coord-1", "coordinator", period["version"], "north")
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")

        # Coordinator reconfirms under the (still covering) new band.
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-2", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        self.assertEqual(item["status"], "suspended")
        self.assertEqual(item["payload"]["suspend_authorization"]["authorization_code"], "REG-NORTH-2")

    def test_period_update_requires_version(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        with self.assertRaises(DomainError) as ctx:
            self.service.update_protection_period(period["id"], "update", self.period_payload, "coord-1", "coordinator", None, "north")
        self.assertEqual(ctx.exception.code, "expected_version_required")

    def test_period_update_version_conflict(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        with self.assertRaises(ConflictError):
            self.service.update_protection_period(period["id"], "update", self.period_payload, "coord-1", "coordinator", 99, "north")

    def test_concurrent_resolve_first_write_wins(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")
        item = self.service.act(item["id"], "coordinate", {"coordination_agreement": "AGC-7"}, "coord-1", "coordinator", item["version"], "north")

        # Both coordinators read the same version.
        version = item["version"]
        first = self.service.act(item["id"], "resolve", {"measurement_cleared": True, "evidence": "scan-7"}, "coord-1", "coordinator", version, "north")
        self.assertEqual(first["status"], "resolved")
        with self.assertRaises(ConflictError):
            self.service.act(item["id"], "resolve", {"measurement_cleared": True, "evidence": "scan-8"}, "coord-2", "coordinator", version, "north")

    def test_idempotent_create_item(self):
        payload = {
            "frequency_mhz": 2450.0,
            "bandwidth_mhz": 20.0,
            "station_id": "ST-01",
            "region": "north",
            "strength_dbm": -40,
            "detected_at": "2026-09-27T10:00:00+00:00",
            "reporter": "monitor-1",
        }
        first = self.service.create_item(payload, "analyst-1", "analyst", request_id="req-create-1")
        second = self.service.create_item(payload, "analyst-1", "analyst", request_id="req-create-1")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.service.list_items()), 1)

    def test_idempotent_action_does_not_duplicate_authorization(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        first = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north", request_id="req-suspend-1")
        second = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north", request_id="req-suspend-1")
        self.assertEqual(first["version"], second["version"])
        self.assertEqual(len(first["audit"]), len(second["audit"]))
        actions = self.repo.list_actions(item["id"])
        suspend_actions = [a for a in actions if a["action"] == "suspend"]
        self.assertEqual(len(suspend_actions), 1)

    def test_idempotent_period_update_does_not_repeat_cascade(self):
        period = self.service.create_protection_period(self.period_payload, "coord-1", "coordinator", "north")
        item = self._create_item()
        item = self.service.act(item["id"], "suspend", {"authorization_code": "REG-NORTH-1", "protection_period_id": period["id"]}, "coord-1", "coordinator", item["version"], "north")

        new_payload = dict(self.period_payload)
        new_payload["frequency_end_mhz"] = 2600.0
        first = self.service.update_protection_period(period["id"], "update", new_payload, "coord-1", "coordinator", period["version"], "north", request_id="req-period-1")
        second = self.service.update_protection_period(period["id"], "update", new_payload, "coord-1", "coordinator", period["version"], "north", request_id="req-period-1")
        self.assertEqual(first["version"], second["version"])

        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "review")
        audit_types = [event["event_type"] for event in item["audit"]]
        self.assertEqual(audit_types.count("protection_period_changed"), 1)


if __name__ == "__main__":
    unittest.main()

from . import domain, rules
from .domain import DomainError


class Service:
    def __init__(self, repository):
        self.repository = repository

    def _require_identity(self, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)

    def _region_guard(self, item, role, region):
        if rules.ENFORCE_REGION and region and role != "regulator":
            if item["payload"].get("region") != region:
                raise DomainError("region_mismatch", "不能处理其他区域的记录", 403)

    def create_item(self, payload, actor, role, region=None, request_id=None):
        self._require_identity(actor, role)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role, request_id
        )

    def add_source(self, item_id, payload, actor, role, region=None, request_id=None):
        self._require_identity(actor, role)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        normalized = domain.normalize_source(payload)
        if region and rules.ENFORCE_REGION and role != "regulator" and normalized.get("region") and normalized["region"] != region:
            raise DomainError("region_mismatch", "来源记录不属于当前管辖区域", 403)
        return self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
            request_id,
        )

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None, request_id=None):
        self._require_identity(actor, role)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        item = self.repository.get_item(item_id)
        if action in rules.REGION_SENSITIVE_ACTIONS:
            self._region_guard(item, role, region)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        if action == "suspend":
            # 早失败提示；权威判定（含并发保护时段变更）在 repository 事务内
            window = self._active_window_for(item["payload"].get("region"))
            if window is None:
                raise DomainError("no_protection_window", "当前区域没有保护时段，不能停用", 409)
            if not rules.item_covered_by_window(item["payload"], window["payload"]):
                raise DomainError(
                    "protection_coverage_mismatch", "干扰频段不在保护时段覆盖范围内，不能停用", 409
                )
        return self.repository.apply_action(
            item_id, action, payload, actor, role, expected_version, request_id
        )

    def create_window(self, payload, actor, role, region=None, request_id=None):
        self._require_identity(actor, role)
        if role not in rules.WINDOW_WRITE_ROLES:
            raise DomainError("forbidden", "只有协调员可以设置保护时段", 403)
        normalized = domain.normalize_window(payload)
        if region and normalized["region"] != region:
            raise DomainError("region_mismatch", "不能为其他区域设置保护时段", 403)
        return self.repository.create_window(normalized, actor, role, request_id)

    def adjust_window(self, window_id, payload, actor, role, expected_version=None, region=None, request_id=None):
        self._require_identity(actor, role)
        if role not in rules.WINDOW_WRITE_ROLES:
            raise DomainError("forbidden", "只有协调员可以变更保护时段", 403)
        if expected_version is None:
            raise DomainError("expected_version_required", "时段变更需要 expected_version", 400)
        window = self.repository.get_window(window_id)
        if region and window["payload"]["region"] != region:
            raise DomainError("region_mismatch", "不能变更其他区域的保护时段", 403)
        normalized = domain.normalize_window(payload)
        if normalized["region"] != window["payload"]["region"]:
            raise DomainError("invalid_window_range", "时段变更不能修改所属区域", 400)
        return self.repository.adjust_window(
            window_id, normalized, expected_version, actor, role, request_id
        )

    def _active_window_for(self, region):
        for window in self.repository.list_windows():
            if window["status"] == "active" and window["payload"].get("region") == region:
                return window
        return None

    def get_item(self, item_id):
        return self.repository.get_item_view(item_id)

    def get_window(self, window_id):
        return self.repository.get_window(window_id)

    def list_windows(self):
        return self.repository.list_windows()

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()

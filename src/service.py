from . import domain, rules
from .domain import ConflictError, DomainError


class Service:
    def __init__(self, repository):
        self.repository = repository

    def create_item(self, payload, actor, role, region=None, request_id=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role, request_id
        )

    def add_source(self, item_id, payload, actor, role, region=None, request_id=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        normalized = domain.normalize_source(payload)
        if region and rules.ENFORCE_REGION and role != "regulator" and normalized.get("region") and normalized["region"] != region:
            raise DomainError("region_mismatch", "来源记录不属于当前管辖区域", 403)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None, request_id=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        if rules.ENFORCE_REGION and action in rules.REGION_SENSITIVE_ACTIONS and region and role != "regulator":
            if item["payload"].get("region") != region:
                raise DomainError("region_mismatch", "不能处理其他区域的记录", 403)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        if not request_id and expected_version is not None and int(expected_version) != int(item["version"]):
            raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")

        protection_period = None
        if action == "suspend":
            period_id = payload.get("protection_period_id")
            if period_id is None:
                raise DomainError("protection_period_required", "停用授权必须关联保护时段")
            protection_period = self.repository.get_protection_period(period_id)
            rules.validate_suspend_coverage(item, protection_period)

        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role, protection_period)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version, request_id
        )
        return self.get_item(item_id)

    def create_protection_period(self, payload, actor, role, region=None, request_id=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.PERIOD_ROLES:
            raise DomainError("forbidden", "当前角色不能设置保护时段", 403)
        normalized = domain.normalize_protection_period(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_protection_period(stable_key, normalized, actor, role, request_id)

    def update_protection_period(self, period_id, action, payload, actor, role, expected_version=None, region=None, request_id=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.PERIOD_ROLES:
            raise DomainError("forbidden", "当前角色不能变更保护时段", 403)
        if action not in rules.PERIOD_ACTIONS:
            raise DomainError("unknown_action", "不支持的操作")
        if action in rules.PERIOD_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "变更保护时段需要 expected_version", 400)
        period = self.repository.get_protection_period(period_id)
        if rules.ENFORCE_REGION and region and role != "regulator":
            if period.get("region") and period["region"] != region:
                raise DomainError("region_mismatch", "不能变更其他区域的保护时段", 403)
        normalized = domain.normalize_protection_period(payload)
        new_payload = {key: value for key, value in normalized.items() if key != "_stable_key"}
        return self.repository.update_protection_period(period_id, new_payload, actor, role, expected_version, request_id)

    def get_protection_period(self, period_id):
        return self.repository.get_protection_period(period_id)

    def list_protection_periods(self):
        return self.repository.list_protection_periods()

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()

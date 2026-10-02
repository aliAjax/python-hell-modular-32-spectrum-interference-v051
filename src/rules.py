import math

from .domain import DomainError

ENTITY_TYPE = "spectrum_interference"
WINDOW_ENTITY_TYPE = "protection_window"
INITIAL_STATUS = "pending"
CREATE_ROLES = {"analyst", "monitor"}
SOURCE_ROLES = {"analyst", "monitor", "field_operator"}
WINDOW_WRITE_ROLES = {"coordinator"}
ACTION_ROLES = {
    "assess": {"analyst", "monitor"},
    "locate": {"field_operator", "analyst"},
    "suspend": {"coordinator"},
    "reconfirm": {"coordinator"},
    "coordinate": {"coordinator"},
    "resolve": {"coordinator", "regulator"},
    "correct_measurement": {"analyst", "monitor"},
    "cancel": {"coordinator"},
}
ENFORCE_REGION = True
REGION_SENSITIVE_ACTIONS = {"suspend", "reconfirm", "coordinate", "resolve", "cancel"}
ACTION_REQUIRES_VERSION = {"suspend", "reconfirm", "coordinate", "resolve", "cancel"}

# 已经进入处置流程、保护时段调整时需要退回复核的事件状态
DISPOSITION_STATUSES = {"located", "suspended", "coordinating", "review"}
TERMINAL_STATUSES = {"resolved", "cancelled"}
SUSPEND_FROM = {"located"}
RECONFIRM_FROM = {"review"}


def authorization_code(payload):
    code = payload.get("authorization_code")
    if not isinstance(code, str) or not code.strip():
        raise DomainError("field_required", "authorization_code 不能为空")
    code = code.strip()
    if not code.startswith("REG-"):
        raise DomainError("invalid_authorization", "停用授权编号无效", 403)
    return code


def frequency_in_window(item_payload, window):
    """事件频段与保护时段频段相交即视为落在覆盖范围内。

    window 可以是完整行（频段嵌在 payload 中），也可以是已解包的 payload。
    """
    if "payload" in window and isinstance(window["payload"], dict):
        window = window["payload"]
    center = float(item_payload["frequency_mhz"])
    half = float(item_payload.get("bandwidth_mhz", 0.0)) / 2.0
    item_low = center - half
    item_high = center + half
    return item_high > float(window["start_mhz"]) and item_low < float(window["end_mhz"])


def item_covered_by_window(item_payload, window):
    if window is None:
        return False
    if item_payload.get("region") != window["region"]:
        return False
    return frequency_in_window(item_payload, window)


def assess(payload):
    strength = float(payload.get("strength_dbm", -120))
    bandwidth = max(float(payload.get("bandwidth_mhz", 0.1)), 0.001)
    impact = strength + 10.0 * math.log10(bandwidth * 1000.0)
    if impact >= -37:
        level = "critical"
    elif impact >= -50:
        level = "high"
    elif impact >= -65:
        level = "medium"
    else:
        level = "low"
    score = round(max(0.0, min(100.0, 100.0 + impact)), 2)
    return {"score": score, "level": level, "impact_value": round(impact, 2)}


def _need_status(item, allowed):
    if item["status"] not in allowed:
        raise DomainError("invalid_state", "当前状态 %s 不允许执行该操作" % item["status"])


def _text(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DomainError("field_required", "%s 不能为空" % name)
    return value.strip()


def apply_action(item, action, payload, actor, role, authorization=None):
    status = item["status"]
    current = dict(item["payload"])

    if action == "assess":
        _need_status(item, {"pending", "assessed"})
        current["assessment"] = assess(current)
        return "assessed", current, {"assessment": current["assessment"]}

    if action == "correct_measurement":
        _need_status(item, {"pending", "assessed", "located"})
        try:
            strength = float(payload["strength_dbm"])
        except (KeyError, TypeError, ValueError):
            raise DomainError("field_required", "strength_dbm 不能为空")
        revision = {
            "old_strength_dbm": current.get("strength_dbm"),
            "new_strength_dbm": strength,
            "reason": _text(payload, "reason"),
            "actor": actor,
        }
        current.setdefault("measurement_revisions", []).append(revision)
        current["strength_dbm"] = strength
        current["assessment"] = assess(current)
        return status, current, {"revision": revision}

    if action == "locate":
        _need_status(item, {"assessed", "located"})
        location = _text(payload, "location")
        confidence = float(payload.get("confidence", 0))
        if confidence < 0.6:
            raise DomainError("low_location_confidence", "定位置信度低于0.6，不能进入处置", 409)
        current["location"] = {"label": location, "confidence": confidence}
        return "located", current, {"location": current["location"]}

    if action in ("suspend", "reconfirm"):
        # suspend：首次停用，必须落在当前保护时段覆盖范围内（repository 已做事务内校验）
        # reconfirm：保护时段调整后授权失效，协调员在新时段上重新确认
        _need_status(item, {"located"} if action == "suspend" else {"review"})
        if authorization is None:
            raise DomainError("no_protection_window", "当前没有匹配的保护时段，不能停用", 409)
        code = _text(payload, "authorization_code")
        if not code.startswith("REG-"):
            raise DomainError("invalid_authorization", "停用授权编号无效", 403)
        current["suspend_authorization"] = code
        current["authorization_detail"] = authorization
        if action == "reconfirm":
            current.pop("current_review", None)
        return "suspended", current, {
            "authorization_code": code,
            "authorization_id": authorization["id"],
            "window_id": authorization["window_id"],
            "window_version": authorization["window_version"],
            "reconfirmed": action == "reconfirm",
        }

    if action == "coordinate":
        _need_status(item, {"suspended"})
        agreement = _text(payload, "coordination_agreement")
        current["coordination_agreement"] = agreement
        current["coordination_note"] = payload.get("note", "")
        return "coordinating", current, {"coordination_agreement": agreement}

    if action == "resolve":
        _need_status(item, {"coordinating"})
        if not payload.get("measurement_cleared"):
            raise DomainError("interference_present", "干扰尚未消除，不能结案", 409)
        current["resolution"] = {"evidence": _text(payload, "evidence"), "cleared": True}
        return "resolved", current, {"evidence": current["resolution"]["evidence"]}

    if action == "cancel":
        _need_status(item, {"pending", "assessed", "review"})
        reason = _text(payload, "reason")
        current["cancellation"] = {"reason": reason, "actor": actor}
        return "cancelled", current, {"reason": reason}

    raise DomainError("unknown_action", "不支持的操作")

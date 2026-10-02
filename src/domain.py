from datetime import datetime


class DomainError(Exception):
    def __init__(self, code, message, status=400, details=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details


class ConflictError(DomainError):
    def __init__(self, code, message, details=None):
        super().__init__(code, message, 409, details)


class NotFoundError(DomainError):
    def __init__(self, code, message):
        super().__init__(code, message, 404)


class ServiceResult(dict):
    """写操作返回值：dict 本体即响应 JSON，附带 HTTP 状态与幂等回放标记。"""

    def __init__(self, payload, status=200, replayed=False):
        super().__init__(payload)
        self.status = status
        self.replayed = replayed


def require_text(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DomainError("field_required", "%s 不能为空" % name)
    return value.strip()


def number(payload, name, minimum=None, maximum=None):
    value = payload.get(name)
    if isinstance(value, bool):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    if minimum is not None and value < minimum:
        raise DomainError("invalid_number", "%s 不能小于 %s" % (name, minimum))
    if maximum is not None and value > maximum:
        raise DomainError("invalid_number", "%s 不能大于 %s" % (name, maximum))
    return value


def parse_timestamp(payload, name):
    value = require_text(payload, name)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DomainError("invalid_timestamp", "%s 必须是 ISO 时间" % name)
    return value


def normalize_create(payload):
    frequency = number(payload, "frequency_mhz", 0.001, 300000)
    bandwidth = number(payload, "bandwidth_mhz", 0.001)
    station_id = require_text(payload, "station_id")
    region = require_text(payload, "region")
    strength = number(payload, "strength_dbm")
    detected_at = parse_timestamp(payload, "detected_at")
    reporter = require_text(payload, "reporter")
    stable_key = "%s|%s|%s|%s" % (station_id, region, frequency, detected_at)
    return {
        "frequency_mhz": frequency,
        "bandwidth_mhz": bandwidth,
        "station_id": station_id,
        "region": region,
        "strength_dbm": strength,
        "detected_at": detected_at,
        "reporter": reporter,
        "measurement_revisions": [],
        "suspend_authorization": None,
        "_stable_key": stable_key,
    }


def normalize_source(payload):
    source_type = require_text(payload, "source_type")
    external_id = require_text(payload, "external_id")
    observed_at = parse_timestamp(payload, "observed_at")
    strength = number(payload, "strength_dbm")
    region = payload.get("region")
    if region is not None:
        region = str(region).strip() or None
    return {
        "source_type": source_type,
        "external_id": external_id,
        "observed_at": observed_at,
        "strength_dbm": strength,
        "region": region,
        "station_id": payload.get("station_id"),
        "frequency_mhz": payload.get("frequency_mhz"),
    }


def normalize_window(payload):
    region = require_text(payload, "region")
    start_mhz = number(payload, "start_mhz", 0.001, 300000)
    end_mhz = number(payload, "end_mhz", 0.001, 300000)
    if end_mhz <= start_mhz:
        raise DomainError("invalid_window_range", "end_mhz 必须大于 start_mhz")
    starts_at = parse_timestamp(payload, "starts_at")
    ends_at = parse_timestamp(payload, "ends_at")
    if ends_at <= starts_at:
        raise DomainError("invalid_window_range", "ends_at 必须晚于 starts_at")
    label = payload.get("label")
    if label is not None:
        label = str(label).strip() or None
    return {
        "region": region,
        "start_mhz": start_mhz,
        "end_mhz": end_mhz,
        "starts_at": starts_at,
        "ends_at": ends_at,
        "label": label,
    }

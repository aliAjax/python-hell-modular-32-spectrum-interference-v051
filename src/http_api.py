import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from .domain import DomainError, ServiceResult


def build_handler(service, static_dir):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ModularPythonHell/1.0"

        def log_message(self, fmt, *args):
            return

        def _identity(self):
            actor = self.headers.get("X-User-Id", "").strip()
            role = self.headers.get("X-Role", "").strip()
            region = self.headers.get("X-Region", "").strip() or None
            return actor, role, region

        def _json_body(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise DomainError("invalid_json", "请求体不是有效 JSON", 400)

        def _request_id(self, payload):
            value = payload.pop("request_id", None) or self.headers.get("X-Request-Id")
            if value is not None:
                value = str(value).strip() or None
            return value

        def _send(self, status, value, content_type="application/json; charset=utf-8", extra_headers=None):
            if not isinstance(value, (bytes, bytearray)):
                value = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(value)))
            if extra_headers:
                for key, header_value in extra_headers:
                    self.send_header(key, header_value)
            self.end_headers()
            self.wfile.write(value)

        def _send_result(self, result, default_status=200):
            headers = [("X-Idempotent-Replayed", "true" if result.replayed else "false")]
            self._send(result.status or default_status, dict(result), extra_headers=headers)

        def _error(self, exc):
            body = {"error": exc.code, "message": str(exc)}
            details = getattr(exc, "details", None)
            if details:
                body["details"] = details
            self._send(getattr(exc, "status", 500), body)

        def do_GET(self):
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    return self._send(200, {"status": "ok"})
                if path == "/api/state":
                    return self._send(200, service.state())
                if path == "/api/items":
                    return self._send(200, {"items": service.list_items()})
                if path == "/api/windows":
                    return self._send(200, {"windows": service.list_windows()})
                parts = [part for part in path.split("/") if part]
                if len(parts) == 3 and parts[:2] == ["api", "items"]:
                    return self._send(200, service.get_item(int(parts[2])))
                if len(parts) == 4 and parts[:2] == ["api", "items"] and parts[3] == "audit":
                    item = service.get_item(int(parts[2]))
                    return self._send(200, {"events": item["audit"]})
                if len(parts) == 3 and parts[:2] == ["api", "windows"]:
                    return self._send(200, service.get_window(int(parts[2])))
                if path == "/":
                    file_path = os.path.join(static_dir, "index.html")
                    with open(file_path, "rb") as handle:
                        content = handle.read()
                    return self._send(200, content, "text/html; charset=utf-8")
                return self._send(404, {"error": "not_found", "message": "接口不存在"})
            except DomainError as exc:
                return self._error(exc)
            except (ValueError, OSError) as exc:
                return self._error(DomainError("invalid_request", str(exc), 400))

        def do_POST(self):
            try:
                actor, role, region = self._identity()
                path = urlparse(self.path).path
                payload = self._json_body()
                request_id = self._request_id(payload)
                parts = [part for part in path.split("/") if part]
                if parts == ["api", "items"]:
                    result = service.create_item(payload, actor, role, region, request_id)
                    return self._send_result(result, 201)
                if len(parts) == 4 and parts[:2] == ["api", "items"] and parts[3] == "sources":
                    result = service.add_source(int(parts[2]), payload, actor, role, region, request_id)
                    return self._send_result(result, 201)
                if len(parts) == 4 and parts[:2] == ["api", "items"] and parts[3] == "actions":
                    action = payload.pop("action", "")
                    if not action:
                        raise DomainError("action_required", "缺少 action", 400)
                    expected = payload.pop("expected_version", None)
                    result = service.act(
                        int(parts[2]), action, payload, actor, role, expected, region, request_id
                    )
                    return self._send_result(result, 200)
                if parts == ["api", "windows"]:
                    result = service.create_window(payload, actor, role, region, request_id)
                    return self._send_result(result, 201)
                if len(parts) == 4 and parts[:2] == ["api", "windows"] and parts[3] == "adjust":
                    expected = payload.pop("expected_version", None)
                    result = service.adjust_window(
                        int(parts[2]), payload, actor, role, expected, region, request_id
                    )
                    return self._send_result(result, 200)
                return self._send(404, {"error": "not_found", "message": "接口不存在"})
            except DomainError as exc:
                return self._error(exc)
            except Exception as exc:
                return self._error(DomainError("internal_error", str(exc), 500))

    return Handler

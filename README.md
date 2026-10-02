# 无线电频谱干扰调查与协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8332`。

模块结构：`app.py` 负责组装，`src/domain.py` 定义字段、错误和带回放标记的写结果，`src/rules.py` 负责评估、定位、授权、覆盖判断和状态机，`src/repository.py` 管理 SQLite、版本、级联退回复核、幂等请求和审计链，`src/service.py` 编排权限，`src/http_api.py` 提供接口，`src/audit.py` 生成审计哈希。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8332
python3 -m unittest discover -s tests -v
```

使用 `X-User-Id`、`X-Role`、`X-Region` 请求头。

## 接口

- `GET /health`、`GET /api/state`
- `POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions`、`GET /api/items/<id>/audit`
- `POST /api/windows`（协调员设置保护时段，每个区域一条）
- `POST /api/windows/<id>/adjust`（协调员变更时段，必须带 `expected_version`）
- `GET /api/windows`、`GET /api/windows/<id>`

## 保护时段与统一状态

干扰事件、停用授权与保护时段接在同一份版本化状态里：

- 停用（`suspend`）要求事件频段与当前区域**有效**保护时段相交，并携带 `expected_version`。授权记录绑定具体的 `window_id`/`window_version`，事件也锚定到该版本。
- 保护时段调整（`adjust`）在同一事务内：窗口版本 +1 → 该时段全部有效授权立即置为 `invalidated` → 未结案事件退回 `review` 复核态，事件记录 `current_review`（含新覆盖是否匹配）。已结案/已撤销事件保持终态，但授权同样失效。
- `review` 事件由协调员用 `reconfirm` 在新窗口版本上重新确认（新授权，旧授权不复活）；新范围不再覆盖时返回 409 `protection_coverage_mismatch`，事件留在复核态等待协调员确认或撤销。
- 授权失效期间强行 `coordinate`/`resolve` 返回 409 `authorization_invalidated`。

## 并发与重试

- 两名协调员同时结案或变更时段：所有写操作在 `BEGIN IMMEDIATE` 事务内比对 `expected_version`，**先写入者生效**，后到者收到 409 `version_conflict`，响应体 `details.latest` 带最新状态与版本号，客户端据此重做。
- 写请求可带 `X-Request-Id`（或请求体内 `request_id`）。编号在事务内登记，写入失败时随回滚清除，可用同一编号按原请求重试；已完成的请求直接回放原响应（响应头 `X-Idempotent-Replayed: true`），授权记录、动作记录和审计事件都不会重复。同一编号改作其他用途返回 409 `request_id_reused`。

协议接入、真实无线电传播模型和执法权限仍需由外部系统实现。

# 无线电频谱干扰调查与协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8332`。

模块结构：`app.py` 负责组装，`src/domain.py` 定义字段和错误，`src/rules.py` 负责评估、定位、授权和状态机，`src/repository.py` 管理 SQLite、版本和审计链，`src/service.py` 编排权限，`src/http_api.py` 提供接口，`src/audit.py` 生成审计哈希。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8332
python3 -m unittest discover -s tests -v
```

使用 `X-User-Id`、`X-Role`、`X-Region` 请求头，写操作可携带 `X-Request-Id` 进行幂等重试。接口为 `GET /health`、`GET /api/state`、`GET /api/items`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions`、`GET /api/items/<id>/audit`、`GET/POST /api/protection-periods`、`GET /api/protection-periods/<id>` 和 `POST /api/protection-periods/<id>/actions`。

协调员可设置保护时段（时间范围与频段范围）。干扰事件的停用授权必须关联覆盖该事件频率与时间的保护时段；保护时段变更时，其下已发授权立即失效，未结事件退回复核状态，等待协调员重新确认。处置动作与时段变更通过 `expected_version` 进行乐观并发控制，先写入者生效；通过 `X-Request-Id` 重试不会重复已完成的授权与审计。测试覆盖完整调查流程、测量更正、重复事件、跨区越权、定位置信度、版本冲突、保护时段联动与幂等重试。协议接入、真实无线电传播模型和执法权限仍需由外部系统实现。

# ProbeSync 数据格式 JSON Schema

## 概述

本目录包含 ProbeSync 批次结构的 JSON Schema 定义，用于约束和验证探针上传的数据格式。

## 为什么用 JSON Schema 而不是 Protobuf？

在 `probe_sync.proto` 中，批次数据通过 `oneof payload` 承载：

```protobuf
message DataBatch {
  oneof payload {
    CaddyLogBatch caddy_logs = 10;
    AlertBatch alerts = 11;
    DecisionBatch decisions = 12;
  }
}
```

**设计原因**：
1. **文档化**: JSON Schema 作为结构化字段的补充说明
2. **验证**: 可选用于运行时数据一致性检查
3. **可视化**: 便于前后端对齐字段预期

**说明**：Protobuf 仍是唯一的强类型约束来源，Schema 用于补充说明

## Schema 文件

### 1. access_log.schema.json
**对应**: `caddy_logs` (CaddyLogBatch)

**数据来源**: `pkg/rawlogstore/reader.go` 中的 `raw` 字段解析为 CaddyLog

**字段说明**:
- 完整 Caddy 结构化日志字段（见 schema 文件）

**示例**:
```json
[
  {
    "level": "info",
    "ts": 1738419600.123,
    "logger": "http.log.access",
    "msg": "handled request",
    "request": {
      "remote_ip": "192.0.2.1",
      "remote_port": "54321",
      "client_ip": "192.0.2.1",
      "proto": "HTTP/2.0",
      "method": "GET",
      "host": "api.hospital.local",
      "uri": "/api/v1/patients",
      "headers": {"User-Agent": ["Mozilla/5.0"]},
      "tls": {
        "resumed": false,
        "version": 772,
        "cipher_suite": 4865,
        "proto": "h2",
        "server_name": "api.hospital.local"
      }
    },
    "bytes_read": 0,
    "user_id": "doctor-001",
    "duration": 0.123,
    "size": 4567,
    "status": 200,
    "resp_headers": {"Content-Type": ["application/json"]}
  }
]
```

### 2. alert.schema.json
**对应**: `alerts` (AlertBatch)

**数据来源**: `pkg/database/pusher_queries.go` 的 `QueryAlertsAfterID()`

**核心字段**:
- `id`: Alert ID (整数)
- `created_at` / `updated_at`: 创建/更新时间
- `scenario`: 触发场景名称
- `source_value` / `source_scope`: 攻击源信息
- `events_count`: 关联事件数量
- `started_at` / `stopped_at`: 告警时间范围

### 3. decision.schema.json
**对应**: `decisions` (DecisionBatch)

**数据来源**: `pkg/database/pusher_queries.go` 的 `QueryDecisionsAfterID()`

**核心字段**:
- `id`: Decision ID (整数)
- `origin`: 决策来源
- `type`: 决策类型
- `scope`: 作用域
- `value`: 目标值
- `scenario`: 关联场景
- `start_ip/end_ip/...`: IP 范围字段

**示例**:
```json
[
  {
    "id": 123,
    "origin": "crowdsec",
    "type": "ban",
    "scope": "Ip",
    "value": "127.0.0.1",
    "scenario": "crowdsecurity/http-sensitive-files",
    "created_at": "2026-01-31 10:23:21.5957794 +0000 UTC",
    "updated_at": "2026-01-31 10:23:21.5957794 +0000 UTC",
    "until": "2026-01-31 14:23:20.9632127 +0000 UTC",
    "start_ip": -9223372034724069374,
    "end_ip": -9223372034724069374,
    "start_suffix": -9223372036854775807,
    "end_suffix": -9223372036854775807,
    "ip_size": 4,
    "alert_decisions": 1
  }
]
```

## 使用 Schema

### 后端验证 (Go)

使用 `gojsonschema` 库验证接收到的数据：

```go
package main

import (
    "encoding/json"
    "fmt"
    "github.com/xeipuuv/gojsonschema"
)

func ValidateDataBatch(payloadType string, data []byte) error {
    var schemaPath string
    switch payloadType {
    case "caddy_logs":
        schemaPath = "file://./schemas/access_log.schema.json"
    case "alerts":
        schemaPath = "file://./schemas/alert.schema.json"
    case "decisions":
        schemaPath = "file://./schemas/decision.schema.json"
    default:
        return fmt.Errorf("unknown payload type: %s", payloadType)
    }

    schemaLoader := gojsonschema.NewReferenceLoader(schemaPath)
    documentLoader := gojsonschema.NewBytesLoader(data)

    result, err := gojsonschema.Validate(schemaLoader, documentLoader)
    if err != nil {
        return fmt.Errorf("schema validation failed: %w", err)
    }

    if !result.Valid() {
        return fmt.Errorf("data invalid: %v", result.Errors())
    }

    return nil
}
```

### 后端解析 (Go)

根据 DataType 反序列化到对应的 Go 结构：

```go
type CaddyLogRecord struct {
    Level    string                 `json:"level"`
    Ts       float64                `json:"ts"`
    Logger   string                 `json:"logger"`
    Msg      string                 `json:"msg"`
    Request  map[string]interface{} `json:"request"`
    Status   int                    `json:"status"`
    Duration float64                `json:"duration"`
}

func ParseCaddyLogs(data []byte) ([]CaddyLogRecord, error) {
    var records []CaddyLogRecord
    if err := json.Unmarshal(data, &records); err != nil {
        return nil, fmt.Errorf("unmarshal caddy logs: %w", err)
    }
    return records, nil
}
```

### 前端验证 (TypeScript)

使用 `ajv` 库：

```typescript
import Ajv from 'ajv';
import accessLogSchema from './schemas/access_log.schema.json';

const ajv = new Ajv();
const validate = ajv.compile(accessLogSchema);

function validateAccessLogs(data: unknown): boolean {
  const valid = validate(data);
  if (!valid) {
    console.error('Validation errors:', validate.errors);
  }
  return valid;
}
```

## 版本管理

### Schema 版本控制

当数据结构需要演化时：

1. **向后兼容的变更** (推荐):
   - 添加新的可选字段
   - 放宽字段约束 (如允许 null)
   - 直接修改 Schema 文件

2. **破坏性变更** (谨慎):
   - 删除必需字段
   - 修改字段类型
   - 创建新版本 Schema (如 `access_log.v2.schema.json`)
   - 创建新的 payload 类型

### 与 Proto 文件的关系

| 层次 | 文件 | 描述 | 稳定性 |
|------|------|------|--------|
| 传输协议 | `probe_sync.proto` | gRPC 消息结构 | 高 (很少变更) |
| 数据格式 | `*.schema.json` | JSON 数据约束 | 中 (随业务演化) |
| 代码实现 | `models/*.go` | Go 数据结构 | 低 (频繁变更) |

## 工具推荐

### 1. JSON Schema 生成工具

从现有 JSON 数据生成 Schema：
```bash
npm install -g quicktype
quicktype data_sample.json -o schema.json --lang schema
```

### 2. 在线验证器

验证 Schema 格式正确性：
- https://www.jsonschemavalidator.net/

### 3. Go 代码生成

从 Schema 生成 Go 结构体：
```bash
go install github.com/atombender/go-jsonschema/cmd/gojsonschema@latest
gojsonschema -p models access_log.schema.json -o access_log_gen.go
```

## 参考文档

- **数据字段完整示例**: `docs/20260201_2100_VERIFY_探针gRPC上传数据字段完整示例.md`
- **架构设计**: `docs/20260131_2400_ARCH_探针gRPC通信方案_v1.md`
- **JSON Schema 规范**: https://json-schema.org/
- **CrowdSec Models**: `pkg/models/*.go` (生成自 OpenAPI spec)

## 常见问题

### Q: 为什么不在 proto 中用 google.protobuf.Struct？

A: `google.protobuf.Struct` 本质上也是 JSON，但序列化后体积更大：
```
JSON:      {"id":"1","value":"test"}       (27 bytes)
Struct:    {fields:{id:{string_value:"1"},...}}  (~60 bytes)
```

### Q: 性能会受影响吗？

A: JSON 解析比 Protobuf 稍慢，但在网络 I/O 占主导的场景中可忽略：
- Protobuf: ~1 µs per message
- JSON: ~5 µs per message
- gRPC 网络延迟: ~1000 µs (1ms)

### Q: 如何确保探针和后端使用相同的 Schema 版本？

A: 
1. 将 Schema 文件纳入版本管理 (Git)
2. 在 Heartbeat 中添加 schema_version 字段 (可选)
3. 使用语义化版本 (如 v1.2.3)
4. 通过 CI/CD 确保测试覆盖所有 Schema

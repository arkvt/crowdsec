# ProbeSync 数据格式 JSON Schema

## 概述

本目录包含 `DataBatch.data` 字段的 JSON Schema 定义，用于约束和验证探针上传的数据格式。

## 为什么用 JSON Schema 而不是 Protobuf？

在 `probe_sync.proto` 中，`DataBatch.data` 字段定义为 `bytes` 类型：

```protobuf
message DataBatch {
  bytes data = 3;  // JSON 编码的数据数组
}
```

**设计原因**：
1. **灵活性**: JSON 允许数据结构独立于 proto 文件演化
2. **复用性**: 直接使用 CrowdSec 现有的 Go 数据模型 (models.Alert/Decision)
3. **兼容性**: 老版本后端可以忽略新增字段
4. **维护性**: 避免在 proto 和 Go struct 中重复定义相同结构

**权衡**：失去了 Protobuf 的编译期类型检查

**解决方案**：使用 JSON Schema 提供运行时验证和文档化

## Schema 文件

### 1. access_log.schema.json
**对应**: `DATA_TYPE_ACCESS_LOGS` (DataType = 1)

**数据来源**: `pkg/database/pusher_queries.go` 的 `GetAccessLogsAfterCursor()`

**字段说明**:
- `id`: 数据库 rowid (字符串表示)
- `acquis_type`: 采集器类型 (如 "caddy")
- `module`: 模块名称
- `labels`: 元数据标签对象
- `src`: 数据源标识
- `ts`: ISO 8601 时间戳
- `raw`: 原始日志内容 (Caddy 结构化日志的 JSON 字符串)

**示例**:
```json
[
  {
    "id": "1",
    "acquis_type": "caddy",
    "module": "caddy",
    "labels": {
      "type": "caddy"
    },
    "src": "caddy-logs",
    "ts": "2026-02-01T12:00:00Z",
    "raw": "{\"level\":\"info\",\"ts\":1738419600.123,\"request\":{\"remote_ip\":\"192.0.2.1\",...}}"
  }
]
```

### 2. alert.schema.json
**对应**: `DATA_TYPE_ALERTS` (DataType = 2)

**数据来源**: `pkg/database/pusher_queries.go` 的 `GetAlertsAfterCursor()`

**核心字段**:
- `id`: Alert ID (整数)
- `scenario`: 触发场景名称 (如 "crowdsecurity/http-probing")
- `source_value`: 攻击源值
- `source_scope`: 攻击源作用域 (ip/range/as/country)
- `events_count`: 关联事件数量
- `start_at` / `stop_at`: 告警时间范围

**注意**: 此结构对应 CrowdSec `models.Alert`，字段较多，详见 Schema 文件。

### 3. decision.schema.json
**对应**: `DATA_TYPE_DECISIONS` (DataType = 3)

**数据来源**: `pkg/database/pusher_queries.go` 的 `GetDecisionsAfterCursor()`

**核心字段**:
- `id`: Decision ID (整数)
- `origin`: 决策来源 (cscli/crowdsec/CAPI/...)
- `type`: 决策类型 (ban/captcha/throttle/whitelist)
- `scope`: 作用域 (ip/range/as/country)
- `value`: 目标值 (IP 地址或 CIDR)
- `duration`: 持续时间 (如 "4h")
- `scenario`: 关联场景

**示例**:
```json
[
  {
    "id": 123,
    "origin": "cscli",
    "type": "ban",
    "scope": "ip",
    "value": "192.0.2.100",
    "duration": "4h",
    "scenario": "manual/ban",
    "created_at": "2026-02-01T12:00:00Z"
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

func ValidateDataBatch(dataType pb.DataType, data []byte) error {
    var schemaPath string
    switch dataType {
    case pb.DataType_DATA_TYPE_ACCESS_LOGS:
        schemaPath = "file://./schemas/access_log.schema.json"
    case pb.DataType_DATA_TYPE_ALERTS:
        schemaPath = "file://./schemas/alert.schema.json"
    case pb.DataType_DATA_TYPE_DECISIONS:
        schemaPath = "file://./schemas/decision.schema.json"
    default:
        return fmt.Errorf("unknown data type: %v", dataType)
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
type AccessLogRecord struct {
    ID         string            `json:"id"`
    AcquisType string            `json:"acquis_type"`
    Module     string            `json:"module"`
    Labels     map[string]string `json:"labels"`
    Src        string            `json:"src"`
    Ts         string            `json:"ts"`
    Raw        string            `json:"raw"`
}

func ParseAccessLogs(data []byte) ([]AccessLogRecord, error) {
    var records []AccessLogRecord
    if err := json.Unmarshal(data, &records); err != nil {
        return nil, fmt.Errorf("unmarshal access logs: %w", err)
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
   - 在 `DataType` 枚举中添加新类型

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

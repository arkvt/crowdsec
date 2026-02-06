# Pusher 模块实现说明 (gRPC)

## 概述

Pusher 模块实现了 CrowdSec 探针与后端的 **gRPC 双向流** 通信，解决了内网探针无公网 IP、后端无法主动连接探针的问题。

## 架构

```
探针 (内网)                     后端 (公网)
    │                              │
    │══════ gRPC Connect() ═══════│  (单一双向流)
    │                              │
    │───► DataBatch ─────────────►│  (数据上报)
    │◄─── BatchAck ◄──────────────│  (确认)
    │◄─── Command ◄───────────────│  (指令下发)
    │───► CommandAck ────────────►│  (执行结果)
    │───► Heartbeat ─────────────►│  (心跳)
    │◄─── HeartbeatAck ◄─────────│
```

## 文件结构

```
pkg/
├── probesync/
│   ├── generate.go           # go:generate 指令
│   └── proto/
│       ├── probe_sync.proto  # gRPC 协议定义
│       ├── probe_sync.pb.go  # protoc 生成
│       └── probe_sync_grpc.pb.go
├── csconfig/
│   └── pusher.go             # gRPC 配置结构
└── pusher/
    ├── grpc_pusher.go        # gRPC 客户端主逻辑
    ├── sender.go             # 数据发送协程
    ├── receiver.go           # 指令接收协程
    ├── executor.go           # 指令执行器
    ├── state.go              # 游标状态持久化
    ├── doc.go                # 包文档
    ├── config_example.yaml   # 配置示例
    └── README.md             # 本文档
```

## 功能模块

### 1. gRPC 客户端 (grpc_pusher.go)

- 建立 gRPC 双向流连接
- 支持 TLS 和 mTLS
- 自动重连与指数退避
- 连接生命周期管理

### 2. 数据发送 (sender.go)

- **access_logs**: 从 rawlogstore 读取访问日志
- **alerts**: 从数据库读取告警
- **decisions**: 从数据库读取决策
- **host_activity_logs**: 从主机层 SQLite 读取文件活动日志
- **host_protection_logs**: 从主机层 SQLite 读取文件保护日志
- **heartbeat**: 定期心跳，报告探针状态
- 游标管理与幂等性保证

### 3. 指令接收 (receiver.go)

- 实时接收后端指令
- 指令执行与结果上报
- 支持的指令类型:
  - `ping`: 连通性测试
  - `force_sync`: 强制同步
  - `add_whitelist` / `remove_whitelist`: 白名单管理
  - `add_decision` / `remove_decision`: 决策管理
  - `update_config`: 配置更新

### 4. 状态管理 (state.go)

- JSON 格式存储游标
- 原子写入（temp file + rename）
- 线程安全（sync.RWMutex）

## 配置示例

```yaml
crowdsec_service:
  pusher:
    enabled: true
    
    # gRPC 连接
    backend_addr: "backend.example.com:50051"
    probe_id: "prod-gateway-01"
    probe_secret: "sk_probe_xxxxx"
    
    # TLS (可选)
    tls:
      enabled: true
      ca_file: "/path/to/ca.crt"
      # mTLS (可选)
      cert_file: "/path/to/probe.crt"
      key_file: "/path/to/probe.key"
    
    # 数据同步
    sync:
      enabled: true
      access_logs_interval: "60s"
      alerts_interval: "30s"
      decisions_interval: "30s"
      heartbeat_interval: "30s"
      batch_size: 500
      max_batch_bytes: 1048576

    # Host logs SQLite DB path
    host_logs_db_path: "./runtime/host-layer/data/host_logs.db"
    
    # 重连
    reconnect_interval: "5s"
    max_reconnect_interval: "60s"
    
    # 状态持久化
    state_file: "./data/pusher-state.json"
```

## gRPC 协议

### 服务定义

```protobuf
service ProbeSync {
  rpc Connect(stream ProbeMessage) returns (stream BackendMessage);
}
```

### 消息类型

**探针 → 后端:**
- `Heartbeat`: 心跳 + 状态
- `DataBatch`: 数据批次
- `CommandAck`: 指令执行结果

**后端 → 探针:**
- `HeartbeatAck`: 心跳确认
- `BatchAck`: 批次确认
- `Command`: 指令下发
- `ConfigUpdate`: 配置更新

## 幂等性

每个数据批次使用稳定的 `batch_id`:
```
{probe_id}-{payload}-{from_cursor}-{to_cursor}
```

后端对相同 `batch_id` 返回 `ACK_STATUS_DUPLICATE`，探针视为成功。

## 重连机制

- 初始延迟: `reconnect_interval` (默认 5s)
- 指数退避因子: 1.6
- 最大延迟: `max_reconnect_interval` (默认 60s)
- gRPC 内置 keepalive (30s)

## 后端接口要求

后端需实现 gRPC 服务:

```go
type ProbeSyncServer interface {
    Connect(ProbeSync_ConnectServer) error
}
```

核心逻辑:
1. 验证 metadata 认证信息
2. 维护探针连接状态
3. 接收 DataBatch → 存储 → 返回 BatchAck
4. 接收 Heartbeat → 更新状态 → 返回 HeartbeatAck
5. 推送 Command → 等待 CommandAck

## 生成 Proto 代码

```bash
# 安装工具
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# 生成代码
cd pkg/probesync
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/probe_sync.proto
```

## 对比旧方案

| 维度 | HTTP 长轮询 (旧) | gRPC 双向流 (新) |
|------|-----------------|-----------------|
| 连接数 | 2 条 | 1 条 |
| 序列化 | JSON | Protobuf (更小) |
| 指令延迟 | 秒级 | 毫秒级 |
| 重连 | 手动实现 | 内置 |
| 类型安全 | 无 | Proto 强类型 |

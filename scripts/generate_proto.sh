#!/bin/bash
# Protobuf 代码生成脚本

set -e

PROTO_DIR="pkg/probesync/proto"
PROTO_FILE="$PROTO_DIR/probe_sync.proto"
OUTPUT_DIR="pkg/probesync/pb"

echo "🔨 Generating Go code from $PROTO_FILE..."

# 检查 protoc 是否安装
if ! command -v protoc &> /dev/null; then
    echo "❌ protoc not found. Please install:"
    echo "   scoop install protobuf"
    echo "   or download from https://github.com/protocolbuffers/protobuf/releases"
    exit 1
fi

# 检查 Go 插件是否安装
if ! command -v protoc-gen-go &> /dev/null; then
    echo "📦 Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "📦 Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# 生成代码
protoc \
  --go_out=. \
  --go_opt=paths=source_relative \
  --go-grpc_out=. \
  --go-grpc_opt=paths=source_relative \
  "$PROTO_FILE"

echo "✅ Code generation complete!"
echo "📁 Generated files:"
ls -lh "$OUTPUT_DIR"/*.pb.go

# 验证编译
echo ""
echo "🧪 Verifying generated code compiles..."
if go build -o /dev/null ./pkg/probesync/...; then
    echo "✅ Compilation successful!"
else
    echo "❌ Compilation failed!"
    exit 1
fi

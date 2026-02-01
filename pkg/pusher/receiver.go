package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

const (
	defaultCommandTimeout  = 20 * time.Second
	envCommandTimeout      = "SCARECROW_PUSHER_COMMAND_TIMEOUT"
	defaultCommandDedupTTl = 10 * time.Minute
	envCommandDedupTTL     = "SCARECROW_PUSHER_COMMAND_DEDUP_TTL"
)

type commandCacheEntry struct {
	status    pb.CommandStatus
	result    string
	errMsg    string
	expiresAt time.Time
}

// Receiver 负责从后端 gRPC 流接收消息
type Receiver struct {
	cfg         *csconfig.PusherCfg
	executor    *Executor
	logger      *log.Entry
	cmdTimeout  time.Duration
	cmdDedupTTL time.Duration
	cmdCache    map[string]commandCacheEntry
	cmdMu       sync.Mutex
}

// NewReceiver 创建 Receiver
func NewReceiver(cfg *csconfig.PusherCfg, executor *Executor, logger *log.Entry) *Receiver {
	return &Receiver{
		cfg:         cfg,
		executor:    executor,
		logger:      logger.WithField("module", "receiver"),
		cmdTimeout:  envDuration(envCommandTimeout, defaultCommandTimeout),
		cmdDedupTTL: envDuration(envCommandDedupTTL, defaultCommandDedupTTl),
		cmdCache:    make(map[string]commandCacheEntry),
	}
}

// Run 启动接收循环
func (r *Receiver) Run(ctx context.Context, stream pb.ProbeSync_ConnectClient, ackCh chan<- *pb.BatchAck) error {
	r.logger.Info("receiver started")
	defer r.logger.Info("receiver stopped")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				r.logger.Info("stream closed by server")
				return nil
			}
			return fmt.Errorf("recv error: %w", err)
		}

		r.handleMessage(ctx, stream, msg, ackCh)
	}
}

// handleMessage 处理后端消息
func (r *Receiver) handleMessage(ctx context.Context, stream pb.ProbeSync_ConnectClient, msg *pb.BackendMessage, ackCh chan<- *pb.BatchAck) {
	switch payload := msg.Payload.(type) {
	case *pb.BackendMessage_HeartbeatAck:
		r.handleHeartbeatAck(payload.HeartbeatAck)

	case *pb.BackendMessage_BatchAck:
		r.handleBatchAck(payload.BatchAck, ackCh)

	case *pb.BackendMessage_Command:
		r.handleCommand(ctx, stream, payload.Command)

	case *pb.BackendMessage_ConfigUpdate:
		r.handleConfigUpdate(payload.ConfigUpdate)

	default:
		r.logger.Warn("unknown message type received")
	}
}

// handleHeartbeatAck 处理心跳响应
func (r *Receiver) handleHeartbeatAck(ack *pb.HeartbeatAck) {
	r.logger.WithFields(log.Fields{
		"server_time":             ack.ServerTime,
		"config_update_available": ack.ConfigUpdateAvailable,
	}).Debug("heartbeat ack received")

	if ack.ConfigUpdateAvailable {
		r.logger.Info("configuration update available")
		// TODO: 触发配置拉取
	}
}

// handleBatchAck 处理批次确认
func (r *Receiver) handleBatchAck(ack *pb.BatchAck, ackCh chan<- *pb.BatchAck) {
	r.logger.WithFields(log.Fields{
		"batch_id": ack.BatchId,
		"status":   ack.Status.String(),
	}).Debug("batch ack received")

	// 转发给 sender 更新游标
	select {
	case ackCh <- ack:
	default:
		r.logger.Warn("ack channel full, dropping ack")
	}
}

// handleCommand 执行命令并返回结果
func (r *Receiver) handleCommand(ctx context.Context, stream pb.ProbeSync_ConnectClient, cmd *pb.Command) {
	logger := r.logger.WithFields(log.Fields{
		"command_id":   cmd.Id,
		"command_type": cmd.Type.String(),
	})

	logger.Info("command received")
	if r.executor == nil {
		logger.Warn("executor not available")
		r.sendCommandAck(stream, cmd.Id, pb.CommandStatus_COMMAND_STATUS_FAILED, nil, "executor not available")
		return
	}

	if cmd.Id != "" {
		if cached, ok := r.getCachedCommand(cmd.Id); ok {
			logger.WithField("status", cached.status.String()).Info("command duplicate, using cached result")
			if err := r.sendCachedCommandAck(stream, cmd.Id, cached); err != nil {
				logger.WithError(err).Warn("failed to send cached command ack")
			}
			return
		}
	}

	// 将 CommandType 转为字符串
	cmdType := commandTypeToString(cmd.Type)

	cmdCtx, cancel := context.WithTimeout(ctx, r.cmdTimeout)
	defer cancel()

	result, err := r.executor.Execute(cmdCtx, cmdType, json.RawMessage(cmd.Params))
	if err != nil {
		logger.WithError(err).Warn("command execution failed")
		r.sendCommandAck(stream, cmd.Id, pb.CommandStatus_COMMAND_STATUS_FAILED, nil, err.Error())
		return
	}

	logger.Info("command executed successfully")
	if cmd.Id != "" {
		if cached, cacheErr := r.cacheCommandResult(result); cacheErr != nil {
			logger.WithError(cacheErr).Warn("failed to cache command result")
		} else {
			r.setCachedCommand(cmd.Id, cached)
		}
	}
	if err := r.sendCommandAck(stream, cmd.Id, pb.CommandStatus_COMMAND_STATUS_SUCCESS, result, ""); err != nil {
		logger.WithError(err).Warn("failed to send command ack")
	}
}

// handleConfigUpdate 处理配置更新
func (r *Receiver) handleConfigUpdate(update *pb.ConfigUpdate) {
	r.logger.WithFields(log.Fields{
		"version": update.Version,
		"size":    len(update.Config),
	}).Info("config update received")

	// TODO: 应用配置更新
	// 1. 校验新配置
	// 2. 写入磁盘
	// 3. 触发 reload
}

// commandTypeToString 将 proto 枚举转为字符串
func commandTypeToString(t pb.CommandType) string {
	switch t {
	case pb.CommandType_COMMAND_TYPE_PING:
		return "ping"
	case pb.CommandType_COMMAND_TYPE_FORCE_SYNC:
		return "force_sync"
	case pb.CommandType_COMMAND_TYPE_ADD_WHITELIST:
		return "add_whitelist"
	case pb.CommandType_COMMAND_TYPE_REMOVE_WHITELIST:
		return "remove_whitelist"
	case pb.CommandType_COMMAND_TYPE_ADD_DECISION:
		return "add_decision"
	case pb.CommandType_COMMAND_TYPE_REMOVE_DECISION:
		return "remove_decision"
	case pb.CommandType_COMMAND_TYPE_UPDATE_CONFIG:
		return "update_config"
	default:
		return "unknown"
	}
}

func (r *Receiver) sendCommandAck(stream pb.ProbeSync_ConnectClient, commandID string, status pb.CommandStatus, result interface{}, errMsg string) error {
	ack := &pb.CommandAck{
		CommandId: commandID,
		Status:    status,
		Error:     errMsg,
	}

	if result != nil {
		resultJSON, err := json.Marshal(result)
		if err != nil {
			ack.Status = pb.CommandStatus_COMMAND_STATUS_FAILED
			ack.Error = fmt.Sprintf("marshal result failed: %v", err)
		} else {
			ack.Result = string(resultJSON)
		}
	}

	msg := &pb.ProbeMessage{
		ProbeId: r.cfg.ProbeID,
		Payload: &pb.ProbeMessage_CommandAck{
			CommandAck: ack,
		},
	}

	return stream.Send(msg)
}

func (r *Receiver) getCachedCommand(commandID string) (commandCacheEntry, bool) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()

	entry, ok := r.cmdCache[commandID]
	if !ok {
		return commandCacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(r.cmdCache, commandID)
		return commandCacheEntry{}, false
	}

	return entry, true
}

func (r *Receiver) setCachedCommand(commandID string, entry commandCacheEntry) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()

	if time.Now().After(entry.expiresAt) {
		return
	}
	r.cmdCache[commandID] = entry
}

func (r *Receiver) cacheCommandResult(result interface{}) (commandCacheEntry, error) {
	entry := commandCacheEntry{
		status:    pb.CommandStatus_COMMAND_STATUS_SUCCESS,
		expiresAt: time.Now().Add(r.cmdDedupTTL),
	}

	if result == nil {
		return entry, nil
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return commandCacheEntry{}, fmt.Errorf("marshal result failed: %w", err)
	}

	entry.result = string(resultJSON)
	return entry, nil
}

func (r *Receiver) sendCachedCommandAck(stream pb.ProbeSync_ConnectClient, commandID string, cached commandCacheEntry) error {
	ack := &pb.CommandAck{
		CommandId: commandID,
		Status:    cached.status,
		Error:     cached.errMsg,
		Result:    cached.result,
	}

	msg := &pb.ProbeMessage{
		ProbeId: r.cfg.ProbeID,
		Payload: &pb.ProbeMessage_CommandAck{
			CommandAck: ack,
		},
	}

	return stream.Send(msg)
}

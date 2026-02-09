package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

const (
	defaultCommandTimeout = 35 * time.Second
	envCommandTimeout     = "SCARECROW_PUSHER_COMMAND_TIMEOUT"
)

// Receiver 负责从后端 gRPC 流接收消息
type Receiver struct {
	cfg        *csconfig.PusherCfg
	executor   *Executor
	sender     MessageSender
	logger     *log.Entry
	cmdTimeout time.Duration
	cmdSem     chan struct{}
	ackQueue   *CommandAckQueue
}

// NewReceiver 创建 Receiver
func NewReceiver(cfg *csconfig.PusherCfg, executor *Executor, sender MessageSender, logger *log.Entry) *Receiver {
	receiverLogger := logger.WithField("module", "receiver")

	var ackQueue *CommandAckQueue
	if cfg != nil {
		queue, err := NewCommandAckQueue(cfg.ProbeID, cfg.StateFile, sender, receiverLogger)
		if err != nil {
			receiverLogger.WithError(err).Warn("failed to initialize command ack queue")
		} else {
			ackQueue = queue
		}
	}

	return &Receiver{
		cfg:        cfg,
		executor:   executor,
		sender:     sender,
		logger:     receiverLogger,
		cmdTimeout: envDuration(envCommandTimeout, defaultCommandTimeout),
		cmdSem:     make(chan struct{}, 4),
		ackQueue:   ackQueue,
	}
}

// Run 启动接收循环
func (r *Receiver) Run(ctx context.Context, stream pb.ProbeSync_ConnectClient, ackCh chan<- *pb.BatchAck) error {
	r.logger.Info("receiver started")
	defer r.logger.Info("receiver stopped")

	if r.ackQueue != nil {
		go r.ackQueue.Run(ctx)
	}

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

		r.handleMessage(ctx, msg, ackCh)
	}
}

// handleMessage 处理后端消息
func (r *Receiver) handleMessage(ctx context.Context, msg *pb.BackendMessage, ackCh chan<- *pb.BatchAck) {
	switch payload := msg.Payload.(type) {
	case *pb.BackendMessage_HeartbeatAck:
		r.handleHeartbeatAck(payload.HeartbeatAck)

	case *pb.BackendMessage_BatchAck:
		r.handleBatchAck(payload.BatchAck, ackCh)

	case *pb.BackendMessage_Command:
		r.handleCommand(ctx, payload.Command)

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
	}).Info("heartbeat ack received")

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
	}).Info("batch ack received")

	// 转发给 sender 更新游标
	select {
	case ackCh <- ack:
	default:
		r.logger.Warn("ack channel full, dropping ack")
	}
}

// handleCommand 执行命令并返回结果
func (r *Receiver) handleCommand(ctx context.Context, cmd *pb.Command) {
	logger := r.logger.WithFields(log.Fields{
		"command_id":   cmd.Id,
		"command_type": cmd.Type.String(),
	})

	logger.Info("command received")
	logger.WithFields(log.Fields{
		"params_size": len(cmd.Params),
		"created_at":  cmd.CreatedAt,
		"expires_at":  cmd.ExpiresAt,
	}).Info("command metadata")
	if r.executor == nil {
		logger.Warn("executor not available")
		if err := r.sendCommandAck(ctx, cmd.Id, pb.CommandStatus_COMMAND_STATUS_FAILED, nil, "executor not available"); err != nil {
			logger.WithError(err).Warn("failed to send command ack")
		}
		return
	}

	go func() {
		r.cmdSem <- struct{}{}
		defer func() {
			<-r.cmdSem
		}()

		// 将 CommandType 转为字符串
		cmdType := commandTypeToString(cmd.Type)

		cmdCtx, cancel := context.WithTimeout(ctx, r.cmdTimeout)
		defer cancel()

		result, err := r.executor.Execute(cmdCtx, cmdType, json.RawMessage(cmd.Params))
		if err != nil {
			logger.WithError(err).Warn("command execution failed")
			if sendErr := r.sendCommandAck(ctx, cmd.Id, pb.CommandStatus_COMMAND_STATUS_FAILED, nil, err.Error()); sendErr != nil {
				logger.WithError(sendErr).Warn("failed to send command ack")
			}
			return
		}

		logger.Info("command executed successfully")
		if sendErr := r.sendCommandAck(ctx, cmd.Id, pb.CommandStatus_COMMAND_STATUS_SUCCESS, result, ""); sendErr != nil {
			logger.WithError(sendErr).Warn("failed to send command ack")
		}
	}()
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
	case pb.COMMAND_TYPE_PING:
		return "ping"
	case pb.COMMAND_TYPE_FORCE_SYNC:
		return "force_sync"
	case pb.COMMAND_TYPE_ADD_WHITELIST:
		return "add_whitelist"
	case pb.COMMAND_TYPE_REMOVE_WHITELIST:
		return "remove_whitelist"
	case pb.COMMAND_TYPE_ADD_DECISION:
		return "add_decision"
	case pb.COMMAND_TYPE_REMOVE_DECISION:
		return "remove_decision"
	case pb.COMMAND_TYPE_UPDATE_CONFIG:
		return "update_config"
	case pb.COMMAND_TYPE_HOST_LOCK_PATH:
		return "host_lock_path"
	case pb.COMMAND_TYPE_HOST_TEMP_UNLOCK_PATH:
		return "host_temp_unlock_path"
	case pb.COMMAND_TYPE_HOST_EMERGENCY_UNLOCK:
		return "host_emergency_unlock"
	case pb.COMMAND_TYPE_HOST_QUERY_STATUS:
		return "host_query_status"
	case pb.COMMAND_TYPE_HOST_APPLY_POLICY:
		return "host_apply_policy"
	default:
		return "unknown"
	}
}

func (r *Receiver) sendCommandAck(ctx context.Context, commandID string, status pb.CommandStatus, result interface{}, errMsg string) error {
	if r.sender == nil {
		return fmt.Errorf("message sender not configured")
	}
	probeID := ""
	if r.cfg != nil {
		probeID = r.cfg.ProbeID
	}

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
		ProbeId: probeID,
		Payload: &pb.ProbeMessage_CommandAck{
			CommandAck: ack,
		},
	}

	if err := r.sender.Send(ctx, msg); err != nil {
		if r.ackQueue == nil {
			return err
		}
		if queueErr := r.ackQueue.Enqueue(ack); queueErr != nil {
			return fmt.Errorf("send command ack failed: %w; queue command ack failed: %v", err, queueErr)
		}
		r.logger.WithFields(log.Fields{
			"command_id": commandID,
			"status":     ack.Status.String(),
		}).WithError(err).Warn("command ack send failed, persisted for retry")
		return nil
	}

	return nil
}

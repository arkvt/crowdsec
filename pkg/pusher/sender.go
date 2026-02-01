package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
	"github.com/crowdsecurity/crowdsec/pkg/rawlogstore"
)

const (
	defaultAckTimeout        = 15 * time.Second
	defaultSendRetries       = 2
	defaultSendRetryBase     = 500 * time.Millisecond
	defaultHeartbeatInterval = 30 * time.Second
	defaultProbeVersion      = "unknown"

	envAckTimeout    = "SCARECROW_PUSHER_ACK_TIMEOUT"
	envSendRetries   = "SCARECROW_PUSHER_SEND_RETRIES"
	envSendRetryBase = "SCARECROW_PUSHER_SEND_RETRY_BASE"
	envProbeVersion  = "SCARECROW_PROBE_VERSION"
)

// Sender 负责通过 gRPC 流发送数据与心跳
type Sender struct {
	cfg           *csconfig.PusherCfg
	state         *State
	rawlogReader  *rawlogstore.Reader
	dbClient      *database.Client
	logger        *log.Entry
	startTime     time.Time
	ackTimeout    time.Duration
	sendRetries   int
	sendRetryBase time.Duration

	// pendingAcks 用于等待特定 batch 的 ACK
	pendingAcks map[string]chan *pb.BatchAck
	pendingMu   sync.Mutex
}

// NewSender 创建 Sender
func NewSender(cfg *csconfig.PusherCfg, state *State, rawlogReader *rawlogstore.Reader, dbClient *database.Client, logger *log.Entry) *Sender {
	return &Sender{
		cfg:           cfg,
		state:         state,
		rawlogReader:  rawlogReader,
		dbClient:      dbClient,
		logger:        logger.WithField("module", "sender"),
		pendingAcks:   make(map[string]chan *pb.BatchAck),
		startTime:     time.Now(),
		ackTimeout:    envDuration(envAckTimeout, defaultAckTimeout),
		sendRetries:   envInt(envSendRetries, defaultSendRetries),
		sendRetryBase: envDuration(envSendRetryBase, defaultSendRetryBase),
	}
}

// Run 启动发送循环
func (s *Sender) Run(ctx context.Context, stream pb.ProbeSync_ConnectClient, ackCh <-chan *pb.BatchAck) error {
	s.logger.Info("sender started")
	defer s.logger.Info("sender stopped")

	// ACK 处理协程
	go s.handleAcks(ctx, ackCh)

	heartbeatInterval := s.heartbeatInterval()
	heartbeatTicker := time.NewTicker(heartbeatInterval)

	accessLogsTicker := time.NewTicker(s.syncInterval("access_logs"))
	alertsTicker := time.NewTicker(s.syncInterval("alerts"))
	decisionsTicker := time.NewTicker(s.syncInterval("decisions"))

	defer heartbeatTicker.Stop()
	defer accessLogsTicker.Stop()
	defer alertsTicker.Stop()
	defer decisionsTicker.Stop()

	// 发送初始心跳
	if err := s.sendHeartbeat(ctx, stream); err != nil {
		return fmt.Errorf("initial heartbeat failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-heartbeatTicker.C:
			if err := s.sendHeartbeat(ctx, stream); err != nil {
				return fmt.Errorf("heartbeat failed: %w", err)
			}

		case <-accessLogsTicker.C:
			if s.rawlogReader != nil {
				if err := s.syncAccessLogs(ctx, stream); err != nil {
					s.logger.WithError(err).Warn("access logs sync failed")
				}
			}

		case <-alertsTicker.C:
			if s.dbClient != nil {
				if err := s.syncAlerts(ctx, stream); err != nil {
					s.logger.WithError(err).Warn("alerts sync failed")
				}
			}

		case <-decisionsTicker.C:
			if s.dbClient != nil {
				if err := s.syncDecisions(ctx, stream); err != nil {
					s.logger.WithError(err).Warn("decisions sync failed")
				}
			}
		}
	}
}

// handleAcks 处理 BatchAck 消息
func (s *Sender) handleAcks(ctx context.Context, ackCh <-chan *pb.BatchAck) {
	for {
		select {
		case <-ctx.Done():
			return
		case ack, ok := <-ackCh:
			if !ok {
				return
			}
			s.dispatchAck(ack)
		}
	}
}

// dispatchAck 将 ACK 投递给等待者
func (s *Sender) dispatchAck(ack *pb.BatchAck) {
	s.pendingMu.Lock()
	ch, ok := s.pendingAcks[ack.BatchId]
	s.pendingMu.Unlock()

	if !ok {
		s.logger.WithField("batch_id", ack.BatchId).Warn("ack received without waiter")
		return
	}

	select {
	case ch <- ack:
	default:
		s.logger.WithField("batch_id", ack.BatchId).Warn("ack channel full")
	}
}

// sendHeartbeat 发送心跳消息
func (s *Sender) sendHeartbeat(ctx context.Context, stream pb.ProbeSync_ConnectClient) error {
	status := &pb.ProbeStatus{
		Version:       s.probeVersion(),
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
	}

	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    status,
			},
		},
	}

	if err := s.sendWithRetry(ctx, stream, msg); err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	s.logger.Debug("heartbeat sent")
	return nil
}

// syncAccessLogs 同步 access_logs 到后端
func (s *Sender) syncAccessLogs(ctx context.Context, stream pb.ProbeSync_ConnectClient) error {
	cursorStr := s.state.GetCursor("access_logs")
	var cursor int64 = 0
	if cursorStr != "" {
		var err error
		cursor, err = strconv.ParseInt(cursorStr, 10, 64)
		if err != nil {
			s.logger.WithError(err).Warn("invalid access_logs cursor, resetting")
			cursor = 0
		}
	}

	// 从 rawlogstore 读取日志
	result, err := s.rawlogReader.Query(ctx, cursor, s.cfg.Sync.BatchSize, nil)
	if err != nil {
		return fmt.Errorf("failed to read access logs: %w", err)
	}

	if len(result.Items) == 0 {
		return nil
	}

	fromID := result.Items[0].ID
	toID := result.Items[len(result.Items)-1].ID

	items, data, err := limitSliceByBytes(result.Items, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build access logs batch: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	// 若被裁剪，更新范围
	fromID = items[0].ID
	toID = items[len(items)-1].ID

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-access_logs-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				Type:       pb.DataType_DATA_TYPE_ACCESS_LOGS,
				Data:       data,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	ackWaiter := s.registerAck(batchID)
	if err := s.sendWithRetry(ctx, stream, msg); err != nil {
		s.unregisterAck(batchID)
		return fmt.Errorf("failed to send access logs batch: %w", err)
	}

	if err := s.waitAndCommitAck(ctx, batchID, ackWaiter, "access_logs", toID); err != nil {
		s.logger.WithError(err).Warn("access logs batch not acknowledged")
	}

	s.logger.WithFields(log.Fields{
		"batch_id": batchID,
		"count":    len(items),
		"from":     fromID,
		"to":       toID,
	}).Info("access logs batch sent")

	return nil
}

// syncAlerts 同步 alerts 到后端
func (s *Sender) syncAlerts(ctx context.Context, stream pb.ProbeSync_ConnectClient) error {
	cursorStr := s.state.GetCursor("alerts")
	var cursor int64 = 0
	if cursorStr != "" {
		var err error
		cursor, err = strconv.ParseInt(cursorStr, 10, 64)
		if err != nil {
			cursor = 0
		}
	}

	// 从数据库读取 alerts
	alerts, err := s.dbClient.QueryAlertsAfterID(ctx, int(cursor), s.cfg.Sync.BatchSize)
	if err != nil {
		return fmt.Errorf("failed to query alerts: %w", err)
	}

	if len(alerts) == 0 {
		return nil
	}

	items, data, err := limitSliceByBytes(alerts, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build alerts batch: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	fromID := int64(items[0].ID)
	toID := int64(items[len(items)-1].ID)

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-alerts-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				Type:       pb.DataType_DATA_TYPE_ALERTS,
				Data:       data,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	ackWaiter := s.registerAck(batchID)
	if err := s.sendWithRetry(ctx, stream, msg); err != nil {
		s.unregisterAck(batchID)
		return fmt.Errorf("failed to send alerts batch: %w", err)
	}

	if err := s.waitAndCommitAck(ctx, batchID, ackWaiter, "alerts", toID); err != nil {
		s.logger.WithError(err).Warn("alerts batch not acknowledged")
	}

	s.logger.WithFields(log.Fields{
		"batch_id": batchID,
		"count":    len(items),
	}).Info("alerts batch sent")

	return nil
}

// syncDecisions 同步 decisions 到后端
func (s *Sender) syncDecisions(ctx context.Context, stream pb.ProbeSync_ConnectClient) error {
	cursorStr := s.state.GetCursor("decisions")
	var cursor int64 = 0
	if cursorStr != "" {
		var err error
		cursor, err = strconv.ParseInt(cursorStr, 10, 64)
		if err != nil {
			cursor = 0
		}
	}

	// 从数据库读取 decisions
	decisions, err := s.dbClient.QueryDecisionsAfterID(ctx, int(cursor), s.cfg.Sync.BatchSize)
	if err != nil {
		return fmt.Errorf("failed to query decisions: %w", err)
	}

	if len(decisions) == 0 {
		return nil
	}

	items, data, err := limitSliceByBytes(decisions, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build decisions batch: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	fromID := int64(items[0].ID)
	toID := int64(items[len(items)-1].ID)

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-decisions-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				Type:       pb.DataType_DATA_TYPE_DECISIONS,
				Data:       data,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	ackWaiter := s.registerAck(batchID)
	if err := s.sendWithRetry(ctx, stream, msg); err != nil {
		s.unregisterAck(batchID)
		return fmt.Errorf("failed to send decisions batch: %w", err)
	}

	if err := s.waitAndCommitAck(ctx, batchID, ackWaiter, "decisions", toID); err != nil {
		s.logger.WithError(err).Warn("decisions batch not acknowledged")
	}

	s.logger.WithFields(log.Fields{
		"batch_id": batchID,
		"count":    len(items),
	}).Info("decisions batch sent")

	return nil
}

func (s *Sender) waitAndCommitAck(ctx context.Context, batchID string, ackWaiter chan *pb.BatchAck, dataType string, cursor int64) error {
	ack, err := s.waitForAck(ctx, batchID, ackWaiter)
	if err != nil {
		return err
	}

	logger := s.logger.WithField("batch_id", batchID)
	switch ack.Status {
	case pb.AckStatus_ACK_STATUS_OK, pb.AckStatus_ACK_STATUS_DUPLICATE:
		if err := s.state.UpdateAndSave(dataType, strconv.FormatInt(cursor, 10)); err != nil {
			logger.WithError(err).Warn("failed to save cursor")
		}
		return nil
	case pb.AckStatus_ACK_STATUS_ERROR:
		return fmt.Errorf("batch rejected: %s", ack.Error)
	default:
		return fmt.Errorf("unknown ack status: %s", ack.Status.String())
	}
}

func (s *Sender) waitForAck(ctx context.Context, batchID string, ch chan *pb.BatchAck) (*pb.BatchAck, error) {
	defer s.unregisterAck(batchID)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ack := <-ch:
		return ack, nil
	case <-time.After(s.ackTimeout):
		return nil, fmt.Errorf("ack timeout after %s", s.ackTimeout)
	}
}

func (s *Sender) registerAck(batchID string) chan *pb.BatchAck {
	ch := make(chan *pb.BatchAck, 1)
	s.pendingMu.Lock()
	s.pendingAcks[batchID] = ch
	s.pendingMu.Unlock()
	return ch
}

func (s *Sender) unregisterAck(batchID string) {
	s.pendingMu.Lock()
	delete(s.pendingAcks, batchID)
	s.pendingMu.Unlock()
}

func (s *Sender) sendWithRetry(ctx context.Context, stream pb.ProbeSync_ConnectClient, msg *pb.ProbeMessage) error {
	var lastErr error
	retries := s.sendRetries
	if retries < 0 {
		retries = 0
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if err := stream.Send(msg); err == nil {
			return nil
		} else {
			lastErr = err
			s.logger.WithFields(log.Fields{
				"attempt": attempt + 1,
				"error":   err,
			}).Warn("stream send failed")
		}

		if attempt == retries {
			break
		}

		backoff := s.sendRetryBase * time.Duration(1<<attempt)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return lastErr
}

func (s *Sender) heartbeatInterval() time.Duration {
	if s.cfg == nil || s.cfg.Sync == nil || s.cfg.Sync.HeartbeatIntervalDuration <= 0 {
		return defaultHeartbeatInterval
	}
	return s.cfg.Sync.HeartbeatIntervalDuration
}

func (s *Sender) maxBatchBytes() int {
	if s.cfg == nil || s.cfg.Sync == nil {
		return 0
	}
	return s.cfg.Sync.MaxBatchBytes
}

func (s *Sender) syncInterval(dataType string) time.Duration {
	if s.cfg == nil || s.cfg.Sync == nil {
		return time.Hour
	}

	if s.cfg.Sync.Enabled != nil && !*s.cfg.Sync.Enabled {
		return time.Hour
	}

	switch dataType {
	case "access_logs":
		if s.cfg.Sync.AccessLogsIntervalDuration > 0 {
			return s.cfg.Sync.AccessLogsIntervalDuration
		}
	case "alerts":
		if s.cfg.Sync.AlertsIntervalDuration > 0 {
			return s.cfg.Sync.AlertsIntervalDuration
		}
	case "decisions":
		if s.cfg.Sync.DecisionsIntervalDuration > 0 {
			return s.cfg.Sync.DecisionsIntervalDuration
		}
	}

	return time.Hour
}

func (s *Sender) probeVersion() string {
	if v := os.Getenv(envProbeVersion); v != "" {
		return v
	}
	return defaultProbeVersion
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func limitSliceByBytes[T any](items []T, maxBytes int) ([]T, []byte, error) {
	if len(items) == 0 {
		return items, nil, nil
	}

	if maxBytes <= 0 {
		data, err := json.Marshal(items)
		return items, data, err
	}

	data, err := json.Marshal(items)
	if err != nil {
		return nil, nil, err
	}
	if len(data) <= maxBytes {
		return items, data, nil
	}

	for i := len(items) - 1; i >= 1; i-- {
		data, err = json.Marshal(items[:i])
		if err != nil {
			return nil, nil, err
		}
		if len(data) <= maxBytes {
			return items[:i], data, nil
		}
	}

	return nil, nil, fmt.Errorf("batch too large even with 1 item")
}

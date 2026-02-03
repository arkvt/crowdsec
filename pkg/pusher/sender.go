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

	items, usedCount, err := limitCaddyLogsByBytes(result.Items, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build access logs batch: %w", err)
	}
	if len(items) == 0 || usedCount == 0 {
		return nil
	}

	// 若被裁剪，更新范围
	if usedCount < len(result.Items) {
		toID = result.Items[usedCount-1].ID
	}

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-caddy_logs-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Payload: &pb.DataBatch_CaddyLogs{
					CaddyLogs: &pb.CaddyLogBatch{
						Items: items,
					},
				},
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

	items, err := limitAlertsByBytes(alerts, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build alerts batch: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	fromID := items[0].Id
	toID := items[len(items)-1].Id

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-alerts-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Payload: &pb.DataBatch_Alerts{
					Alerts: &pb.AlertBatch{
						Items: items,
					},
				},
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

	items, err := limitDecisionsByBytes(decisions, s.maxBatchBytes())
	if err != nil {
		return fmt.Errorf("failed to build decisions batch: %w", err)
	}
	if len(items) == 0 {
		return nil
	}

	fromID := items[0].Id
	toID := items[len(items)-1].Id

	// 生成 batch ID
	batchID := fmt.Sprintf("%s-decisions-%d-%d", s.cfg.ProbeID, fromID, toID)

	// 发送批次
	msg := &pb.ProbeMessage{
		ProbeId: s.cfg.ProbeID,
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    batchID,
				CursorFrom: fromID,
				CursorTo:   toID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Payload: &pb.DataBatch_Decisions{
					Decisions: &pb.DecisionBatch{
						Items: items,
					},
				},
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

type stringOrNumber string

func (s *stringOrNumber) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = stringOrNumber(str)
		return nil
	}

	var num int64
	if err := json.Unmarshal(data, &num); err == nil {
		*s = stringOrNumber(strconv.FormatInt(num, 10))
		return nil
	}

	return fmt.Errorf("invalid stringOrNumber: %s", string(data))
}

type caddyLogRaw struct {
	Level       string              `json:"level"`
	Ts          float64             `json:"ts"`
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     *caddyRequestRaw    `json:"request"`
	BytesRead   int64               `json:"bytes_read"`
	UserID      string              `json:"user_id"`
	Duration    float64             `json:"duration"`
	Size        int64               `json:"size"`
	Status      uint32              `json:"status"`
	RespHeaders map[string][]string `json:"resp_headers"`
}

type caddyRequestRaw struct {
	RemoteIP   string              `json:"remote_ip"`
	RemotePort stringOrNumber      `json:"remote_port"`
	ClientIP   string              `json:"client_ip"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
	TLS        *caddyTLSRaw        `json:"tls"`
}

type caddyTLSRaw struct {
	Resumed     bool   `json:"resumed"`
	Version     uint32 `json:"version"`
	CipherSuite uint32 `json:"cipher_suite"`
	Proto       string `json:"proto"`
	ServerName  string `json:"server_name"`
}

func toStringListMap(input map[string][]string) map[string]*pb.StringList {
	if len(input) == 0 {
		return nil
	}

	output := make(map[string]*pb.StringList, len(input))
	for key, values := range input {
		output[key] = &pb.StringList{Values: values}
	}
	return output
}

func limitCaddyLogsByBytes(items []rawlogstore.AccessLog, maxBytes int) ([]*pb.CaddyLog, int, error) {
	if len(items) == 0 {
		return nil, 0, nil
	}

	logs := make([]*pb.CaddyLog, 0, len(items))
	for _, item := range items {
		var rawLog caddyLogRaw
		if err := json.Unmarshal([]byte(item.Raw), &rawLog); err != nil {
			return nil, 0, fmt.Errorf("parse caddy log id=%d: %w", item.ID, err)
		}

		var request *pb.CaddyRequest
		if rawLog.Request != nil {
			request = &pb.CaddyRequest{
				RemoteIp:   rawLog.Request.RemoteIP,
				RemotePort: string(rawLog.Request.RemotePort),
				ClientIp:   rawLog.Request.ClientIP,
				Proto:      rawLog.Request.Proto,
				Method:     rawLog.Request.Method,
				Host:       rawLog.Request.Host,
				Uri:        rawLog.Request.URI,
				Headers:    toStringListMap(rawLog.Request.Headers),
			}
			if rawLog.Request.TLS != nil {
				request.Tls = &pb.CaddyTls{
					Resumed:     rawLog.Request.TLS.Resumed,
					Version:     rawLog.Request.TLS.Version,
					CipherSuite: rawLog.Request.TLS.CipherSuite,
					Proto:       rawLog.Request.TLS.Proto,
					ServerName:  rawLog.Request.TLS.ServerName,
				}
			}
		}

		logEntry := &pb.CaddyLog{
			Level:       rawLog.Level,
			Ts:          rawLog.Ts,
			Logger:      rawLog.Logger,
			Msg:         rawLog.Msg,
			Request:     request,
			BytesRead:   rawLog.BytesRead,
			UserId:      rawLog.UserID,
			Duration:    rawLog.Duration,
			Size:        rawLog.Size,
			Status:      rawLog.Status,
			RespHeaders: toStringListMap(rawLog.RespHeaders),
		}
		logs = append(logs, logEntry)
	}

	if maxBytes <= 0 {
		return logs, len(logs), nil
	}

	data, err := json.Marshal(logs)
	if err != nil {
		return nil, 0, err
	}
	if len(data) <= maxBytes {
		return logs, len(logs), nil
	}

	for i := len(logs) - 1; i >= 1; i-- {
		data, err = json.Marshal(logs[:i])
		if err != nil {
			return nil, 0, err
		}
		if len(data) <= maxBytes {
			return logs[:i], i, nil
		}
	}

	return nil, 0, fmt.Errorf("batch too large even with 1 item")
}

func limitAlertsByBytes(items []*database.PusherAlert, maxBytes int) ([]*pb.Alert, error) {
	if len(items) == 0 {
		return nil, nil
	}

	alerts := make([]*pb.Alert, 0, len(items))
	for _, item := range items {
		alerts = append(alerts, &pb.Alert{
			Id:              int64(item.ID),
			CreatedAt:       item.CreatedAt,
			UpdatedAt:       item.UpdatedAt,
			Scenario:        item.Scenario,
			BucketId:        item.BucketID,
			Message:         item.Message,
			EventsCount:     int32(item.EventsCount),
			StartedAt:       item.StartedAt,
			StoppedAt:       item.StoppedAt,
			SourceIp:        item.SourceIP,
			SourceRange:     item.SourceRange,
			SourceAsNumber:  item.SourceASNumber,
			SourceAsName:    item.SourceASName,
			SourceCountry:   item.SourceCountry,
			SourceLatitude:  float64(item.SourceLatitude),
			SourceLongitude: float64(item.SourceLongitude),
			SourceScope:     item.SourceScope,
			SourceValue:     item.SourceValue,
			Capacity:        int32(item.Capacity),
			LeakSpeed:       item.LeakSpeed,
			ScenarioVersion: item.ScenarioVersion,
			ScenarioHash:    item.ScenarioHash,
			Simulated:       item.Simulated,
			Uuid:            item.UUID,
			Remediation:     item.Remediation,
			MachineAlerts:   int64(item.MachineAlerts),
		})
	}

	if maxBytes <= 0 {
		return alerts, nil
	}

	data, err := json.Marshal(alerts)
	if err != nil {
		return nil, err
	}
	if len(data) <= maxBytes {
		return alerts, nil
	}

	for i := len(alerts) - 1; i >= 1; i-- {
		data, err = json.Marshal(alerts[:i])
		if err != nil {
			return nil, err
		}
		if len(data) <= maxBytes {
			return alerts[:i], nil
		}
	}

	return nil, fmt.Errorf("batch too large even with 1 item")
}

func limitDecisionsByBytes(items []*database.PusherDecision, maxBytes int) ([]*pb.Decision, error) {
	if len(items) == 0 {
		return nil, nil
	}

	decisions := make([]*pb.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, &pb.Decision{
			Id:             int64(item.ID),
			CreatedAt:      item.CreatedAt,
			UpdatedAt:      item.UpdatedAt,
			Until:          item.Until,
			Scenario:       item.Scenario,
			Type:           item.Type,
			StartIp:        item.StartIP,
			EndIp:          item.EndIP,
			StartSuffix:    item.StartSuffix,
			EndSuffix:      item.EndSuffix,
			IpSize:         item.IPSize,
			Scope:          item.Scope,
			Value:          item.Value,
			Origin:         item.Origin,
			Simulated:      item.Simulated,
			Uuid:           item.UUID,
			AlertDecisions: int64(item.AlertDecisions),
		})
	}

	if maxBytes <= 0 {
		return decisions, nil
	}

	data, err := json.Marshal(decisions)
	if err != nil {
		return nil, err
	}
	if len(data) <= maxBytes {
		return decisions, nil
	}

	for i := len(decisions) - 1; i >= 1; i-- {
		data, err = json.Marshal(decisions[:i])
		if err != nil {
			return nil, err
		}
		if len(data) <= maxBytes {
			return decisions[:i], nil
		}
	}

	return nil, fmt.Errorf("batch too large even with 1 item")
}

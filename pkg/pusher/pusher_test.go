package pusher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

func TestState(t *testing.T) {
	// Create temp dir
	tmpDir, err := os.MkdirTemp("", "pusher-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.WithField("test", "state")

	// Create new state
	state, err := NewState(statePath, logger)
	if err != nil {
		t.Fatalf("NewState failed: %v", err)
	}

	// Test set/get cursor
	state.SetCursor("access_logs", "100")
	cursor := state.GetCursor("access_logs")
	if cursor != "100" {
		t.Errorf("expected cursor 100, got %s", cursor)
	}

	// Test save and reload
	err = state.Save()
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create new state from same file
	state2, err := NewState(statePath, logger)
	if err != nil {
		t.Fatalf("NewState (reload) failed: %v", err)
	}

	cursor2 := state2.GetCursor("access_logs")
	if cursor2 != "100" {
		t.Errorf("expected reloaded cursor 100, got %s", cursor2)
	}
}

func TestStateAtomicWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pusher-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	statePath := filepath.Join(tmpDir, "state.json")
	logger := log.WithField("test", "state")

	state, err := NewState(statePath, logger)
	if err != nil {
		t.Fatalf("NewState failed: %v", err)
	}

	// Update multiple cursors
	state.SetCursor("access_logs", "100")
	state.SetCursor("alerts", "50")
	state.SetCursor("decisions", "25")

	err = state.Save()
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify no temp file left
	tmpPath := statePath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file should not exist after save")
	}

	// Verify content
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}

	var stateData StateData
	if err := json.Unmarshal(data, &stateData); err != nil {
		t.Fatalf("failed to unmarshal state: %v", err)
	}

	if stateData.Cursors["access_logs"] != "100" {
		t.Errorf("expected access_logs cursor 100, got %s", stateData.Cursors["access_logs"])
	}
	if stateData.Cursors["alerts"] != "50" {
		t.Errorf("expected alerts cursor 50, got %s", stateData.Cursors["alerts"])
	}
}

func TestExecutorPing(t *testing.T) {
	logger := log.WithField("test", "executor")
	executor := NewExecutor(nil, nil, logger, nil)

	ctx := context.Background()
	result, err := executor.Execute(ctx, "ping", nil)
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}

	if pong, ok := resultMap["pong"].(bool); !ok || !pong {
		t.Errorf("expected pong=true, got %v", resultMap["pong"])
	}

	if _, ok := resultMap["timestamp"].(string); !ok {
		t.Errorf("expected timestamp string, got %T", resultMap["timestamp"])
	}
}

func TestExecutorForceSync(t *testing.T) {
	logger := log.WithField("test", "executor")
	executor := NewExecutor(nil, nil, logger, nil)

	ctx := context.Background()
	result, err := executor.Execute(ctx, "force_sync", nil)
	if err != nil {
		t.Fatalf("force_sync failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}

	if ack, ok := resultMap["acknowledged"].(bool); !ok || !ack {
		t.Errorf("expected acknowledged=true, got %v", resultMap["acknowledged"])
	}
}

func TestExecutorAddWhitelist(t *testing.T) {
	logger := log.WithField("test", "executor")
	executor := NewExecutor(nil, nil, logger, nil)

	ctx := context.Background()
	params := json.RawMessage(`{"ip": "192.168.1.100", "reason": "trusted host"}`)

	_, err := executor.Execute(ctx, "add_whitelist", params)
	if err == nil {
		t.Fatalf("expected error without LAPI credentials")
	}
}

func TestExecutorUnknownCommand(t *testing.T) {
	logger := log.WithField("test", "executor")
	executor := NewExecutor(nil, nil, logger, nil)

	ctx := context.Background()
	_, err := executor.Execute(ctx, "unknown_command", nil)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestCommandTypeToString(t *testing.T) {
	testCases := []struct {
		cmdType  pb.CommandType
		expected string
	}{
		{pb.CommandType_COMMAND_TYPE_PING, "ping"},
		{pb.CommandType_COMMAND_TYPE_FORCE_SYNC, "force_sync"},
		{pb.CommandType_COMMAND_TYPE_ADD_WHITELIST, "add_whitelist"},
		{pb.CommandType_COMMAND_TYPE_REMOVE_WHITELIST, "remove_whitelist"},
		{pb.CommandType_COMMAND_TYPE_ADD_DECISION, "add_decision"},
		{pb.CommandType_COMMAND_TYPE_REMOVE_DECISION, "remove_decision"},
		{pb.CommandType_COMMAND_TYPE_UPDATE_CONFIG, "update_config"},
		{pb.CommandType_COMMAND_TYPE_HOST_LOCK_PATH, "host_lock_path"},
		{pb.CommandType_COMMAND_TYPE_HOST_TEMP_UNLOCK_PATH, "host_temp_unlock_path"},
		{pb.CommandType_COMMAND_TYPE_HOST_EMERGENCY_UNLOCK, "host_emergency_unlock"},
		{pb.CommandType_COMMAND_TYPE_HOST_QUERY_STATUS, "host_query_status"},
		{pb.CommandType_COMMAND_TYPE_HOST_APPLY_POLICY, "host_apply_policy"},
		{pb.CommandType_COMMAND_TYPE_UNSPECIFIED, "unknown"},
	}

	for _, tc := range testCases {
		result := commandTypeToString(tc.cmdType)
		if result != tc.expected {
			t.Errorf("commandTypeToString(%v) = %s, want %s", tc.cmdType, result, tc.expected)
		}
	}
}

func TestPusherConfig(t *testing.T) {
	cfg := &csconfig.PusherCfg{
		BackendAddr:                  "backend.example.com:50051",
		ProbeID:                      "test-probe",
		ProbeSecret:                  "test-secret",
		ReconnectIntervalDuration:    5 * time.Second,
		MaxReconnectIntervalDuration: 60 * time.Second,
		StateFile:                    "/tmp/test-state.json",
		Sync: &csconfig.PusherSyncCfg{
			AccessLogsIntervalDuration: 60 * time.Second,
			AlertsIntervalDuration:     30 * time.Second,
			DecisionsIntervalDuration:  30 * time.Second,
			HeartbeatIntervalDuration:  30 * time.Second,
			BatchSize:                  500,
			MaxBatchBytes:              1048576,
		},
		TLS: &csconfig.PusherTLSCfg{
			Enabled: false,
		},
	}

	if cfg.BackendAddr != "backend.example.com:50051" {
		t.Errorf("unexpected backend_addr: %s", cfg.BackendAddr)
	}

	if cfg.Sync.BatchSize != 500 {
		t.Errorf("unexpected batch_size: %d", cfg.Sync.BatchSize)
	}
}

func TestProtoMessages(t *testing.T) {
	// Test ProbeMessage creation
	msg := &pb.ProbeMessage{
		ProbeId: "test-probe",
		Payload: &pb.ProbeMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status: &pb.ProbeStatus{
					Version:           "1.0.0",
					UptimeSeconds:     3600,
					PendingAccessLogs: 100,
					PendingAlerts:     10,
					PendingDecisions:  5,
				},
			},
		},
	}

	if msg.ProbeId != "test-probe" {
		t.Errorf("unexpected probe_id: %s", msg.ProbeId)
	}

	hb := msg.GetHeartbeat()
	if hb == nil {
		t.Fatal("expected heartbeat payload")
	}

	if hb.Status.Version != "1.0.0" {
		t.Errorf("unexpected version: %s", hb.Status.Version)
	}

	// Test DataBatch creation
	batchMsg := &pb.ProbeMessage{
		ProbeId: "test-probe",
		Payload: &pb.ProbeMessage_DataBatch{
			DataBatch: &pb.DataBatch{
				BatchId:    "test-probe-caddy_logs-0-100",
				CursorFrom: 0,
				CursorTo:   100,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Payload: &pb.DataBatch_CaddyLogs{
					CaddyLogs: &pb.CaddyLogBatch{
						Items: []*pb.CaddyLog{
							{
								Level:     "info",
								Ts:        1738419600.123,
								Logger:    "http.log.access",
								Msg:       "handled request",
								BytesRead: 0,
								Duration:  0.123,
								Size:      456,
								Status:    200,
							},
						},
					},
				},
			},
		},
	}

	batch := batchMsg.GetDataBatch()
	if batch == nil {
		t.Fatal("expected data_batch payload")
	}

	if batch.CursorFrom != 0 || batch.CursorTo != 100 {
		t.Errorf("unexpected cursor range: %d-%d", batch.CursorFrom, batch.CursorTo)
	}

	if batch.GetCaddyLogs() == nil {
		t.Fatal("expected caddy_logs payload")
	}
}

func TestBackendMessage(t *testing.T) {
	// Test BatchAck
	ackMsg := &pb.BackendMessage{
		Payload: &pb.BackendMessage_BatchAck{
			BatchAck: &pb.BatchAck{
				BatchId: "test-probe-access_logs-0-100",
				Status:  pb.AckStatus_ACK_STATUS_OK,
			},
		},
	}

	ack := ackMsg.GetBatchAck()
	if ack == nil {
		t.Fatal("expected batch_ack payload")
	}

	if ack.Status != pb.AckStatus_ACK_STATUS_OK {
		t.Errorf("unexpected status: %v", ack.Status)
	}

	// Test Command
	cmdMsg := &pb.BackendMessage{
		Payload: &pb.BackendMessage_Command{
			Command: &pb.Command{
				Id:        "cmd-123",
				Type:      pb.CommandType_COMMAND_TYPE_ADD_WHITELIST,
				Params:    []byte(`{"ip":"192.168.1.100"}`),
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	cmd := cmdMsg.GetCommand()
	if cmd == nil {
		t.Fatal("expected command payload")
	}

	if cmd.Type != pb.CommandType_COMMAND_TYPE_ADD_WHITELIST {
		t.Errorf("unexpected command type: %v", cmd.Type)
	}
}

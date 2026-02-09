package pusher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

type flakyAckSender struct {
	mu        sync.Mutex
	failCount int
	sent      []*pb.ProbeMessage
}

func (s *flakyAckSender) Send(ctx context.Context, msg *pb.ProbeMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failCount > 0 {
		s.failCount--
		return fmt.Errorf("send failed")
	}

	s.sent = append(s.sent, msg)
	return nil
}

func (s *flakyAckSender) sentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sent)
}

func (s *flakyAckSender) lastCommandAck() *pb.CommandAck {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sent) == 0 {
		return nil
	}

	return s.sent[len(s.sent)-1].GetCommandAck()
}

func TestCommandAckQueuePersistsAndFlushesAfterRestart(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "command-ack-queue-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	stateFile := filepath.Join(tmpDir, "pusher-state.json")
	queueFile := stateFile + commandAckQueueSuffix
	logger := log.WithField("test", "command_ack_queue")

	senderDown := &flakyAckSender{failCount: 1}
	queue, err := NewCommandAckQueue("probe-1", stateFile, senderDown, logger)
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}

	ack := &pb.CommandAck{
		CommandId: "cmd-1",
		Status:    pb.CommandStatus_COMMAND_STATUS_FAILED,
		Error:     "boom",
	}
	if err := queue.Enqueue(ack); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if _, err := os.Stat(queueFile); err != nil {
		t.Fatalf("queue file should exist: %v", err)
	}

	if err := queue.Flush(context.Background()); err == nil {
		t.Fatal("expected first flush to fail")
	}
	if senderDown.sentCount() != 0 {
		t.Fatalf("expected no sent acks, got %d", senderDown.sentCount())
	}

	senderUp := &flakyAckSender{}
	queueAfterRestart, err := NewCommandAckQueue("probe-1", stateFile, senderUp, logger)
	if err != nil {
		t.Fatalf("new queue after restart: %v", err)
	}
	if err := queueAfterRestart.Flush(context.Background()); err != nil {
		t.Fatalf("flush after restart: %v", err)
	}

	if senderUp.sentCount() != 1 {
		t.Fatalf("expected 1 resent ack, got %d", senderUp.sentCount())
	}
	sentAck := senderUp.lastCommandAck()
	if sentAck == nil {
		t.Fatal("expected command ack payload")
	}
	if sentAck.CommandId != "cmd-1" {
		t.Fatalf("unexpected command id: %s", sentAck.CommandId)
	}

	if _, err := os.Stat(queueFile); !os.IsNotExist(err) {
		t.Fatalf("queue file should be removed after successful flush, err=%v", err)
	}
}

func TestReceiverSendCommandAckQueuesWhenSendFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "receiver-ack-queue-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	stateFile := filepath.Join(tmpDir, "pusher-state.json")
	queueFile := stateFile + commandAckQueueSuffix
	logger := log.WithField("test", "receiver")

	cfg := &csconfig.PusherCfg{
		ProbeID:   "probe-1",
		StateFile: stateFile,
	}

	senderDown := &flakyAckSender{failCount: 1000}
	receiverDown := NewReceiver(cfg, nil, senderDown, logger)

	if err := receiverDown.sendCommandAck(context.Background(), "cmd-2", pb.CommandStatus_COMMAND_STATUS_SUCCESS, map[string]interface{}{"ok": true}, ""); err != nil {
		t.Fatalf("sendCommandAck should fallback to queue, got error: %v", err)
	}

	if _, err := os.Stat(queueFile); err != nil {
		t.Fatalf("queue file should exist after fallback enqueue: %v", err)
	}

	senderUp := &flakyAckSender{}
	receiverUp := NewReceiver(cfg, nil, senderUp, logger)
	if receiverUp.ackQueue == nil {
		t.Fatal("expected ack queue to be initialized")
	}

	if err := receiverUp.ackQueue.Flush(context.Background()); err != nil {
		t.Fatalf("flush queued ack: %v", err)
	}

	if senderUp.sentCount() != 1 {
		t.Fatalf("expected 1 resent ack, got %d", senderUp.sentCount())
	}
	ack := senderUp.lastCommandAck()
	if ack == nil {
		t.Fatal("expected command ack payload")
	}
	if ack.CommandId != "cmd-2" {
		t.Fatalf("unexpected command id: %s", ack.CommandId)
	}
	if ack.Status != pb.CommandStatus_COMMAND_STATUS_SUCCESS {
		t.Fatalf("unexpected ack status: %s", ack.Status.String())
	}
	if ack.Result == "" {
		t.Fatal("expected ack result json")
	}
}

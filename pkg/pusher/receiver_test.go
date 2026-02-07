package pusher

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

type captureSender struct {
	ch  chan *pb.ProbeMessage
	err error
}

func (s *captureSender) Send(ctx context.Context, msg *pb.ProbeMessage) error {
	s.ch <- msg
	return s.err
}

func TestReceiverCommandFailureAck(t *testing.T) {
	logger := log.WithField("test", "receiver")
	sender := &captureSender{ch: make(chan *pb.ProbeMessage, 1)}
	cfg := &csconfig.PusherCfg{ProbeID: "probe-1"}
	executor := NewExecutor(nil, nil, logger, nil)
	receiver := NewReceiver(cfg, executor, sender, logger)

	cmd := &pb.Command{
		Id:     "cmd-1",
		Type:   pb.CommandType_COMMAND_TYPE_REMOVE_DECISION,
		Params: []byte(`{}`),
	}
	msg := &pb.BackendMessage{
		Payload: &pb.BackendMessage_Command{
			Command: cmd,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	receiver.handleMessage(ctx, msg, make(chan *pb.BatchAck, 1))

	select {
	case out := <-sender.ch:
		ack := out.GetCommandAck()
		if ack == nil {
			t.Fatal("expected command ack message")
		}
		if ack.CommandId != "cmd-1" {
			t.Fatalf("unexpected command id: %s", ack.CommandId)
		}
		if ack.Status != pb.CommandStatus_COMMAND_STATUS_FAILED {
			t.Fatalf("expected failed status, got %s", ack.Status.String())
		}
		if ack.Error == "" {
			t.Fatal("expected error message in ack")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for command ack")
	}
}

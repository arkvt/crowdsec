package pusher

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"

	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

type fakeStream struct {
	ctx       context.Context
	mu        sync.Mutex
	sent      []*pb.ProbeMessage
	failAfter int
	sendCount int
}

func (f *fakeStream) Send(msg *pb.ProbeMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sendCount++
	if f.failAfter > 0 && f.sendCount > f.failAfter {
		return errors.New("send failed")
	}
	f.sent = append(f.sent, msg)
	return nil
}

func (f *fakeStream) Recv() (*pb.BackendMessage, error) {
	return nil, io.EOF
}

func (f *fakeStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (f *fakeStream) Trailer() metadata.MD {
	return nil
}

func (f *fakeStream) CloseSend() error {
	return nil
}

func (f *fakeStream) Context() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return context.Background()
}

func (f *fakeStream) SendMsg(m interface{}) error {
	msg, ok := m.(*pb.ProbeMessage)
	if !ok {
		return nil
	}
	return f.Send(msg)
}

func (f *fakeStream) RecvMsg(m interface{}) error {
	return io.EOF
}

func TestSendQueueErrorPropagation(t *testing.T) {
	ctx := context.Background()
	stream := &fakeStream{ctx: ctx, failAfter: 1}
	logger := log.WithField("test", "send_queue")

	queue := NewSendQueue(ctx, stream, logger)

	if err := queue.Send(ctx, &pb.ProbeMessage{ProbeId: "probe-1"}); err != nil {
		t.Fatalf("expected first send to succeed, got %v", err)
	}

	if err := queue.Send(ctx, &pb.ProbeMessage{ProbeId: "probe-2"}); err == nil {
		t.Fatal("expected second send to fail")
	}

	if err := queue.Send(ctx, &pb.ProbeMessage{ProbeId: "probe-3"}); err == nil {
		t.Fatal("expected send after failure to return error")
	}
}

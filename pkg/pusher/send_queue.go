package pusher

import (
	"context"
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"

	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

const sendQueueSize = 100

type MessageSender interface {
	Send(ctx context.Context, msg *pb.ProbeMessage) error
}

type sendRequest struct {
	msg    *pb.ProbeMessage
	result chan error
}

type SendQueue struct {
	stream pb.ProbeSync_ConnectClient
	logger *log.Entry

	ch   chan sendRequest
	done chan struct{}

	errMu sync.Mutex
	err   error
	once  sync.Once
}

func NewSendQueue(ctx context.Context, stream pb.ProbeSync_ConnectClient, logger *log.Entry) *SendQueue {
	l := logger
	if l == nil {
		l = log.New().WithField("module", "send_queue")
	} else {
		l = l.WithField("module", "send_queue")
	}
	q := &SendQueue{
		stream: stream,
		logger: l,
		ch:     make(chan sendRequest, sendQueueSize),
		done:   make(chan struct{}),
	}
	go q.run(ctx)
	return q
}

func (q *SendQueue) Send(ctx context.Context, msg *pb.ProbeMessage) error {
	if msg == nil {
		return errors.New("nil message")
	}
	if err := q.getErr(); err != nil {
		return err
	}

	req := sendRequest{
		msg:    msg,
		result: make(chan error, 1),
	}

	select {
	case <-q.done:
		return q.getErr()
	case q.ch <- req:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-req.result:
		return err
	case <-q.done:
		return q.getErr()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *SendQueue) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			q.closeWithErr(ctx.Err())
			return
		case req, ok := <-q.ch:
			if !ok {
				q.closeWithErr(errors.New("send queue closed"))
				return
			}
			if err := q.stream.Send(req.msg); err != nil {
				q.logger.WithError(err).Warn("stream send failed")
				req.result <- err
				q.closeWithErr(err)
				return
			}
			req.result <- nil
		}
	}
}

func (q *SendQueue) closeWithErr(err error) {
	q.errMu.Lock()
	if q.err == nil {
		q.err = err
	}
	q.errMu.Unlock()

	q.once.Do(func() {
		close(q.done)
	})
}

func (q *SendQueue) getErr() error {
	q.errMu.Lock()
	defer q.errMu.Unlock()
	return q.err
}

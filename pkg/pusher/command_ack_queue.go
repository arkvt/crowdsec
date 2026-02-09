package pusher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

const (
	defaultCommandAckRetryInterval = 5 * time.Second
	commandAckQueueSuffix          = ".command-ack-queue.json"
)

type queuedCommandAck struct {
	CommandID string `json:"command_id"`
	Status    int32  `json:"status"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`

	QueuedAt   string `json:"queued_at"`
	RetryCount int    `json:"retry_count,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

type commandAckQueueFile struct {
	Items []queuedCommandAck `json:"items"`
}

// CommandAckQueue stores failed command acks on disk and retries later.
type CommandAckQueue struct {
	probeID string
	path    string
	sender  MessageSender
	logger  *log.Entry

	retryInterval time.Duration

	mu    sync.Mutex
	items []queuedCommandAck
}

func NewCommandAckQueue(probeID string, stateFile string, sender MessageSender, logger *log.Entry) (*CommandAckQueue, error) {
	if sender == nil {
		return nil, fmt.Errorf("message sender not configured")
	}

	if logger == nil {
		base := log.New()
		logger = log.NewEntry(base)
	}

	path := buildCommandAckQueuePath(probeID, stateFile)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create command ack queue dir: %w", err)
	}

	q := &CommandAckQueue{
		probeID:       probeID,
		path:          path,
		sender:        sender,
		logger:        logger.WithField("module", "command_ack_queue"),
		retryInterval: defaultCommandAckRetryInterval,
		items:         make([]queuedCommandAck, 0),
	}

	if err := q.load(); err != nil {
		return nil, err
	}

	return q, nil
}

func buildCommandAckQueuePath(probeID string, stateFile string) string {
	if stateFile != "" {
		return stateFile + commandAckQueueSuffix
	}

	name := sanitizeProbeID(probeID)
	if name == "" {
		name = "default"
	}

	return filepath.Join(os.TempDir(), fmt.Sprintf("scarecrow-%s%s", name, commandAckQueueSuffix))
}

func sanitizeProbeID(probeID string) string {
	replacer := strings.NewReplacer(
		"\\", "_",
		"/", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)

	return replacer.Replace(strings.TrimSpace(probeID))
}

func (q *CommandAckQueue) load() error {
	data, err := os.ReadFile(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read command ack queue: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	var onDisk commandAckQueueFile
	if err := json.Unmarshal(data, &onDisk); err != nil {
		return fmt.Errorf("unmarshal command ack queue: %w", err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.items = make([]queuedCommandAck, 0, len(onDisk.Items))
	for _, item := range onDisk.Items {
		if item.CommandID == "" {
			continue
		}
		q.items = append(q.items, item)
	}

	return nil
}

func (q *CommandAckQueue) Enqueue(ack *pb.CommandAck) error {
	if ack == nil {
		return fmt.Errorf("command ack is nil")
	}
	if ack.CommandId == "" {
		return fmt.Errorf("command id is empty")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	updated := false
	for i := range q.items {
		if q.items[i].CommandID == ack.CommandId {
			q.items[i].Status = int32(ack.Status)
			q.items[i].Result = ack.Result
			q.items[i].Error = ack.Error
			q.items[i].QueuedAt = now
			q.items[i].RetryCount = 0
			q.items[i].LastError = ""
			updated = true
			break
		}
	}

	if !updated {
		q.items = append(q.items, queuedCommandAck{
			CommandID:  ack.CommandId,
			Status:     int32(ack.Status),
			Result:     ack.Result,
			Error:      ack.Error,
			QueuedAt:   now,
			RetryCount: 0,
			LastError:  "",
		})
	}

	if err := q.saveLocked(); err != nil {
		return err
	}

	q.logger.WithFields(log.Fields{
		"command_id": ack.CommandId,
		"queue_size": len(q.items),
	}).Warn("command ack queued for retry")

	return nil
}

func (q *CommandAckQueue) Flush(ctx context.Context) error {
	for {
		item, ok := q.peek()
		if !ok {
			return nil
		}

		msg := q.toProbeMessage(item)
		if err := q.sender.Send(ctx, msg); err != nil {
			if errMark := q.markFailure(item.CommandID, err); errMark != nil {
				return fmt.Errorf("send command ack failed: %w, and failed to persist retry state: %v", err, errMark)
			}
			return err
		}

		if err := q.remove(item.CommandID); err != nil {
			return err
		}

		q.logger.WithField("command_id", item.CommandID).Info("queued command ack sent")
	}
}

func (q *CommandAckQueue) Run(ctx context.Context) {
	if err := q.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
		q.logger.WithError(err).Warn("initial command ack queue flush failed")
	}

	ticker := time.NewTicker(q.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := q.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
				q.logger.WithError(err).Warn("command ack queue flush failed")
			}
		}
	}
}

func (q *CommandAckQueue) toProbeMessage(item queuedCommandAck) *pb.ProbeMessage {
	ack := &pb.CommandAck{
		CommandId: item.CommandID,
		Status:    pb.CommandStatus(item.Status),
		Result:    item.Result,
		Error:     item.Error,
	}

	return &pb.ProbeMessage{
		ProbeId: q.probeID,
		Payload: &pb.ProbeMessage_CommandAck{
			CommandAck: ack,
		},
	}
}

func (q *CommandAckQueue) peek() (queuedCommandAck, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return queuedCommandAck{}, false
	}

	return q.items[0], true
}

func (q *CommandAckQueue) remove(commandID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i := range q.items {
		if q.items[i].CommandID != commandID {
			continue
		}
		q.items = append(q.items[:i], q.items[i+1:]...)
		return q.saveLocked()
	}

	return nil
}

func (q *CommandAckQueue) markFailure(commandID string, sendErr error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i := range q.items {
		if q.items[i].CommandID != commandID {
			continue
		}
		q.items[i].RetryCount++
		q.items[i].LastError = sendErr.Error()
		break
	}

	return q.saveLocked()
}

func (q *CommandAckQueue) saveLocked() error {
	if len(q.items) == 0 {
		if err := os.Remove(q.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove empty command ack queue: %w", err)
		}
		return nil
	}

	onDisk := commandAckQueueFile{Items: q.items}
	data, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal command ack queue: %w", err)
	}

	tmp := q.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp command ack queue: %w", err)
	}

	if err := os.Rename(tmp, q.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename command ack queue: %w", err)
	}

	return nil
}

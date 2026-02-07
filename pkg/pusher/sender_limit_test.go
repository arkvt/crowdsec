package pusher

import (
	"fmt"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/rawlogstore"
)

func TestLimitCaddyLogsByBytesSkipMalformed(t *testing.T) {
	items := []rawlogstore.AccessLog{
		{ID: 1, Raw: "{invalid json"},
		{ID: 2, Raw: validCaddyRaw("ok", 0)},
	}

	logs, firstValidPos, processedCount, skippedCount, err := limitCaddyLogsByBytes(items, 0, log.New().WithField("test", "limit"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 valid log, got %d", len(logs))
	}
	if firstValidPos != 1 {
		t.Fatalf("expected firstValidPos=1, got %d", firstValidPos)
	}
	if processedCount != 2 {
		t.Fatalf("expected processedCount=2, got %d", processedCount)
	}
	if skippedCount != 1 {
		t.Fatalf("expected skippedCount=1, got %d", skippedCount)
	}
}

func TestLimitCaddyLogsByBytesAllMalformed(t *testing.T) {
	items := []rawlogstore.AccessLog{
		{ID: 10, Raw: "{"},
		{ID: 11, Raw: "not-json"},
	}

	logs, firstValidPos, processedCount, skippedCount, err := limitCaddyLogsByBytes(items, 0, log.New().WithField("test", "limit"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("expected 0 valid logs, got %d", len(logs))
	}
	if firstValidPos != -1 {
		t.Fatalf("expected firstValidPos=-1, got %d", firstValidPos)
	}
	if processedCount != 2 {
		t.Fatalf("expected processedCount=2, got %d", processedCount)
	}
	if skippedCount != 2 {
		t.Fatalf("expected skippedCount=2, got %d", skippedCount)
	}
}

func TestLimitCaddyLogsByBytesDropOversizedSingle(t *testing.T) {
	items := []rawlogstore.AccessLog{
		{ID: 20, Raw: validCaddyRaw("big", 2048)},
	}

	logs, firstValidPos, processedCount, skippedCount, err := limitCaddyLogsByBytes(items, 128, log.New().WithField("test", "limit"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("expected 0 valid logs, got %d", len(logs))
	}
	if firstValidPos != -1 {
		t.Fatalf("expected firstValidPos=-1, got %d", firstValidPos)
	}
	if processedCount != 1 {
		t.Fatalf("expected processedCount=1, got %d", processedCount)
	}
	if skippedCount != 1 {
		t.Fatalf("expected skippedCount=1, got %d", skippedCount)
	}
}

func validCaddyRaw(prefix string, msgPad int) string {
	msg := prefix
	if msgPad > 0 {
		msg = msg + fmt.Sprintf("-%0*s", msgPad, "x")
	}

	return fmt.Sprintf(`{"level":"info","ts":1739000000.1,"logger":"http.log.access","msg":%q,"request":{"remote_ip":"127.0.0.1","remote_port":"12345","client_ip":"127.0.0.1","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/","headers":{"User-Agent":["test"]}},"bytes_read":0,"user_id":"","duration":0.001,"size":123,"status":200,"resp_headers":{"Server":["caddy"]}}`, msg)
}

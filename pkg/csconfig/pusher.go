package csconfig

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

// PusherCfg configures the gRPC push sync to backend
type PusherCfg struct {
	Enabled *bool `yaml:"enabled"`

	// gRPC connection
	BackendAddr string `yaml:"backend_addr"` // gRPC server address (host:port)
	ProbeID     string `yaml:"probe_id"`
	ProbeSecret string `yaml:"probe_secret"`

	// TLS configuration (optional)
	TLS *PusherTLSCfg `yaml:"tls,omitempty"`

	// Sync configuration
	Sync *PusherSyncCfg `yaml:"sync,omitempty"`

	// Reconnect settings
	ReconnectInterval    string `yaml:"reconnect_interval,omitempty"`
	MaxReconnectInterval string `yaml:"max_reconnect_interval,omitempty"`

	// State file for cursor persistence
	StateFile string `yaml:"state_file,omitempty"`

	// Parsed durations (internal)
	ReconnectIntervalDuration    time.Duration `yaml:"-"`
	MaxReconnectIntervalDuration time.Duration `yaml:"-"`
}

// PusherTLSCfg configures TLS for gRPC connection
type PusherTLSCfg struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file,omitempty"`   // Client certificate for mTLS
	KeyFile    string `yaml:"key_file,omitempty"`    // Client key for mTLS
	CAFile     string `yaml:"ca_file,omitempty"`     // CA certificate to verify server
	SkipVerify bool   `yaml:"skip_verify,omitempty"` // Skip server certificate verification
}

// PusherSyncCfg configures data sync intervals
type PusherSyncCfg struct {
	Enabled            *bool  `yaml:"enabled"`
	AccessLogsInterval string `yaml:"access_logs_interval,omitempty"`
	AlertsInterval     string `yaml:"alerts_interval,omitempty"`
	DecisionsInterval  string `yaml:"decisions_interval,omitempty"`
	HostLogsInterval   string `yaml:"host_logs_interval,omitempty"`
	HeartbeatInterval  string `yaml:"heartbeat_interval,omitempty"`
	BatchSize          int    `yaml:"batch_size,omitempty"`
	MaxBatchBytes      int    `yaml:"max_batch_bytes,omitempty"`

	// Parsed durations (internal)
	AccessLogsIntervalDuration time.Duration `yaml:"-"`
	AlertsIntervalDuration     time.Duration `yaml:"-"`
	DecisionsIntervalDuration  time.Duration `yaml:"-"`
	HostLogsIntervalDuration   time.Duration `yaml:"-"`
	HeartbeatIntervalDuration  time.Duration `yaml:"-"`
}

// LoadPusher loads and validates pusher configuration
func (c *Config) LoadPusher() error {
	if c.Crowdsec == nil || c.Crowdsec.Pusher == nil {
		return nil
	}

	p := c.Crowdsec.Pusher

	// Default: disabled
	if p.Enabled == nil {
		p.Enabled = ptr.Of(false)
	}

	if !*p.Enabled {
		return nil
	}

	// Validate required fields
	if p.BackendAddr == "" {
		return fmt.Errorf("pusher.backend_addr is required when pusher is enabled")
	}
	if p.ProbeID == "" {
		return fmt.Errorf("pusher.probe_id is required when pusher is enabled")
	}
	if p.ProbeSecret == "" {
		return fmt.Errorf("pusher.probe_secret is required when pusher is enabled")
	}

	// Reconnect interval
	if p.ReconnectInterval == "" {
		p.ReconnectInterval = "5s"
	}
	d, err := time.ParseDuration(p.ReconnectInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.reconnect_interval: %w", err)
	}
	p.ReconnectIntervalDuration = d

	// Max reconnect interval
	if p.MaxReconnectInterval == "" {
		p.MaxReconnectInterval = "60s"
	}
	d, err = time.ParseDuration(p.MaxReconnectInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.max_reconnect_interval: %w", err)
	}
	p.MaxReconnectIntervalDuration = d

	// State file
	if p.StateFile == "" {
		p.StateFile = filepath.Join(c.ConfigPaths.DataDir, "pusher-state.json")
	}
	if err := ensureAbsolutePath(&p.StateFile); err != nil {
		return err
	}

	// Load TLS config
	if err := loadPusherTLS(p); err != nil {
		return err
	}

	// Load sync config
	if err := loadPusherSync(p); err != nil {
		return err
	}

	return nil
}

func loadPusherTLS(p *PusherCfg) error {
	if p.TLS == nil {
		p.TLS = &PusherTLSCfg{}
	}
	return nil
}

func loadPusherSync(p *PusherCfg) error {
	if p.Sync == nil {
		p.Sync = &PusherSyncCfg{}
	}
	s := p.Sync

	// Default: enabled if pusher is enabled
	if s.Enabled == nil {
		s.Enabled = ptr.Of(true)
	}

	if !*s.Enabled {
		return nil
	}

	// Access logs interval
	if s.AccessLogsInterval == "" {
		s.AccessLogsInterval = "60s"
	}
	d, err := time.ParseDuration(s.AccessLogsInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.sync.access_logs_interval: %w", err)
	}
	s.AccessLogsIntervalDuration = d

	// Alerts interval
	if s.AlertsInterval == "" {
		s.AlertsInterval = "30s"
	}
	d, err = time.ParseDuration(s.AlertsInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.sync.alerts_interval: %w", err)
	}
	s.AlertsIntervalDuration = d

	// Decisions interval
	if s.DecisionsInterval == "" {
		s.DecisionsInterval = "30s"
	}
	d, err = time.ParseDuration(s.DecisionsInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.sync.decisions_interval: %w", err)
	}
	s.DecisionsIntervalDuration = d

	// Host logs interval
	if s.HostLogsInterval == "" {
		s.HostLogsInterval = "30s"
	}
	d, err = time.ParseDuration(s.HostLogsInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.sync.host_logs_interval: %w", err)
	}
	s.HostLogsIntervalDuration = d

	// Heartbeat interval
	if s.HeartbeatInterval == "" {
		s.HeartbeatInterval = "30s"
	}
	d, err = time.ParseDuration(s.HeartbeatInterval)
	if err != nil {
		return fmt.Errorf("invalid pusher.sync.heartbeat_interval: %w", err)
	}
	s.HeartbeatIntervalDuration = d

	// Batch size
	if s.BatchSize == 0 {
		s.BatchSize = 500
	}
	if s.BatchSize > 5000 {
		s.BatchSize = 5000
	}

	// Max batch bytes (default 1MB)
	if s.MaxBatchBytes == 0 {
		s.MaxBatchBytes = 1048576
	}

	return nil
}

package pusher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/hostlogstore"
	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
	"github.com/crowdsecurity/crowdsec/pkg/rawlogstore"
)

const (
	defaultConnectTimeout    = 10 * time.Second
	defaultKeepaliveTime     = 30 * time.Second
	defaultKeepaliveTimeout  = 10 * time.Second
	defaultMinConnectTimeout = 5 * time.Second
	defaultBackoffMultiplier = 1.6
	envPusherConnectTimeout  = "SCARECROW_PUSHER_CONNECT_TIMEOUT"
)

// Pusher 负责与后端建立 gRPC 双向流并维持连接
type Pusher struct {
	cfg           *csconfig.PusherCfg
	state         *State
	rawlogReader  *rawlogstore.Reader
	hostlogReader *hostlogstore.Reader
	dbClient      *database.Client
	executor      *Executor
	logger        *log.Entry

	conn   *grpc.ClientConn
	client pb.ProbeSyncClient
	stream pb.ProbeSync_ConnectClient

	// 用于协调的通道
	ackCh  chan *pb.BatchAck
	stopCh chan struct{}

	stopOnce sync.Once
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

// NewPusher 创建 gRPC Pusher 实例
func NewPusher(cfg *csconfig.PusherCfg, rawlogReader *rawlogstore.Reader, hostlogReader *hostlogstore.Reader, dbClient *database.Client, lapiCfg *csconfig.LocalApiClientCfg) (*Pusher, error) {
	logger := log.WithField("component", "pusher")

	// 加载状态
	state, err := NewState(cfg.StateFile, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	hostStore := (*hostlogstore.CommandStore)(nil)
	if cfg.HostLogsDBPath != "" {
		hostStore, err = hostlogstore.NewCommandStore(cfg.HostLogsDBPath)
		if err != nil {
			logger.WithError(err).Warn("failed to create host command store")
			hostStore = nil
		}
	}

	p := &Pusher{
		cfg:           cfg,
		state:         state,
		rawlogReader:  rawlogReader,
		hostlogReader: hostlogReader,
		dbClient:      dbClient,
		executor:      NewExecutor(dbClient, hostStore, logger, lapiCfg),
		logger:        logger,
		ackCh:         make(chan *pb.BatchAck, 100),
		stopCh:        make(chan struct{}),
	}

	return p, nil
}

// Run 启动 gRPC pusher
func (p *Pusher) Run(ctx context.Context) error {
	p.logger.Info("starting gRPC pusher")

	// 连接后端（失败也继续，让连接管理器负责重连）
	if err := p.connect(ctx); err != nil {
		p.logger.WithError(err).Warn("initial connection failed, will retry")
	}

	// 启动连接管理器
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.connectionManager(ctx)
	}()

	go func() {
		<-ctx.Done()
		p.Stop()
	}()

	return nil
}

// Stop 优雅停止 pusher
func (p *Pusher) Stop() {
	p.stopOnce.Do(func() {
		p.logger.Info("stopping gRPC pusher")
		close(p.stopCh)
		p.wg.Wait()

		p.mu.Lock()
		if p.conn != nil {
			p.conn.Close()
		}
		p.mu.Unlock()

		if p.rawlogReader != nil {
			if err := p.rawlogReader.Close(); err != nil {
				p.logger.WithError(err).Warn("failed to close rawlog reader")
			}
		}
		if p.hostlogReader != nil {
			if err := p.hostlogReader.Close(); err != nil {
				p.logger.WithError(err).Warn("failed to close hostlog reader")
			}
		}

		p.logger.Info("gRPC pusher stopped")
	})
}

// connect 建立 gRPC 连接
func (p *Pusher) connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 关闭已有连接
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
		p.client = nil
		p.stream = nil
	}

	// 构建拨号选项
	connectTimeout := envDuration(envPusherConnectTimeout, defaultConnectTimeout)
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                defaultKeepaliveTime,
			Timeout:             defaultKeepaliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  p.cfg.ReconnectIntervalDuration,
				Multiplier: defaultBackoffMultiplier,
				MaxDelay:   p.cfg.MaxReconnectIntervalDuration,
			},
			MinConnectTimeout: defaultMinConnectTimeout,
		}),
		grpc.WithBlock(),
	}

	// TLS 配置
	if p.cfg.TLS != nil && p.cfg.TLS.Enabled {
		tlsConfig, err := p.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to build TLS config: %w", err)
		}
		if tlsConfig.InsecureSkipVerify {
			p.logger.Warn("tls skip_verify enabled, this is insecure")
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// 建立连接（带超时）
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, p.cfg.BackendAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial backend: %w", err)
	}

	p.conn = conn
	p.client = pb.NewProbeSyncClient(conn)

	// 使用认证 metadata 建立双向流
	md := metadata.Pairs(
		"x-probe-id", p.cfg.ProbeID,
		"x-probe-secret", p.cfg.ProbeSecret,
	)
	streamCtx := metadata.NewOutgoingContext(ctx, md)

	stream, err := p.client.Connect(streamCtx)
	if err != nil {
		p.conn.Close()
		p.conn = nil
		p.client = nil
		return fmt.Errorf("failed to establish stream: %w", err)
	}

	p.stream = stream
	p.logger.WithField("backend", p.cfg.BackendAddr).Info("connected to backend")

	return nil
}

// buildTLSConfig 创建 TLS 配置
func (p *Pusher) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: p.cfg.TLS.SkipVerify,
	}

	// 加载 CA 证书
	if p.cfg.TLS.CAFile != "" {
		caCert, err := os.ReadFile(p.cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// 加载客户端证书（mTLS）
	if p.cfg.TLS.CertFile != "" && p.cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(p.cfg.TLS.CertFile, p.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// connectionManager 管理连接生命周期并拉起收发协程
func (p *Pusher) connectionManager(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
		}

		// Get current stream
		p.mu.RLock()
		stream := p.stream
		p.mu.RUnlock()

		if stream == nil {
			p.handleReconnect(ctx)
			continue
		}

		// 启动 sender/receiver 协程
		streamCtx, streamCancel := context.WithCancel(ctx)
		errCh := make(chan error, 2)
		sendQueue := NewSendQueue(streamCtx, stream, p.logger)

		// Sender
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					p.logger.WithField("panic", r).Error("sender panic")
				}
			}()
			sender := NewSender(p.cfg, p.state, p.rawlogReader, p.hostlogReader, p.dbClient, sendQueue, p.logger)
			if err := sender.Run(streamCtx, p.ackCh); err != nil {
				errCh <- fmt.Errorf("sender error: %w", err)
			}
		}()

		// Receiver
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					p.logger.WithField("panic", r).Error("receiver panic")
				}
			}()
			receiver := NewReceiver(p.cfg, p.executor, sendQueue, p.logger)
			if err := receiver.Run(streamCtx, stream, p.ackCh); err != nil {
				errCh <- fmt.Errorf("receiver error: %w", err)
			}
		}()

		// Wait for error or shutdown
		select {
		case <-ctx.Done():
			streamCancel()
			return
		case <-p.stopCh:
			streamCancel()
			return
		case err := <-errCh:
			p.logger.WithError(err).Warn("stream error, will reconnect")
			streamCancel()
			p.mu.Lock()
			p.stream = nil
			p.mu.Unlock()
		}
	}
}

// handleReconnect 以退避方式重连
func (p *Pusher) handleReconnect(ctx context.Context) {
	delay := p.cfg.ReconnectIntervalDuration
	maxDelay := p.cfg.MaxReconnectIntervalDuration

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
		}

		p.logger.WithField("delay", delay).Info("attempting to reconnect")

		if err := p.connect(ctx); err != nil {
			p.logger.WithError(err).Warn("reconnect failed")

			// 指数退避（可中断）
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-p.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
			delay = time.Duration(float64(delay) * defaultBackoffMultiplier)
			if delay > maxDelay {
				delay = maxDelay
			}
			continue
		}

		// Successfully reconnected
		return
	}
}

// GetState 返回当前状态（用于测试）
func (p *Pusher) GetState() *State {
	return p.state
}

// IsConnected 返回是否已连接
func (p *Pusher) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stream != nil
}

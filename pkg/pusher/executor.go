package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Executor 负责指令执行
type Executor struct {
	dbClient *database.Client
	logger   *log.Entry
	lapiCfg  *csconfig.LocalApiClientCfg
}

// NewExecutor 创建指令执行器
func NewExecutor(dbClient *database.Client, logger *log.Entry, lapiCfg *csconfig.LocalApiClientCfg) *Executor {
	return &Executor{
		dbClient: dbClient,
		logger:   logger,
		lapiCfg:  lapiCfg,
	}
}

// Execute 执行指令并返回结果
func (e *Executor) Execute(ctx context.Context, cmdType string, params json.RawMessage) (interface{}, error) {
	switch cmdType {
	case "add_whitelist":
		return e.executeAddWhitelist(ctx, params)
	case "remove_whitelist":
		return e.executeRemoveWhitelist(ctx, params)
	case "add_decision":
		return e.executeAddDecision(ctx, params)
	case "remove_decision":
		return e.executeRemoveDecision(ctx, params)
	case "ping":
		return e.executePing(ctx)
	case "force_sync":
		return e.executeForceSync(ctx)
	case "update_config":
		return e.executeUpdateConfig(ctx, params)
	default:
		return nil, fmt.Errorf("unknown command type: %s", cmdType)
	}
}

// WhitelistParams 为白名单指令参数
type WhitelistParams struct {
	IP       string `json:"ip,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// DecisionParams 为封禁/解封指令参数
type DecisionParams struct {
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Duration string `json:"duration,omitempty"`
	Origin   string `json:"origin,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

const (
	defaultDecisionDuration = "4h"
	defaultDecisionScenario = "scarecrow/probesync"
	defaultLAPIRetryMax     = 2
	defaultLAPIRetryBase    = 200 * time.Millisecond
	envLAPIRetryMax         = "SCARECROW_PUSHER_LAPI_RETRY_MAX"
	envLAPIRetryBase        = "SCARECROW_PUSHER_LAPI_RETRY_BASE"
)

func envIntWithDefault(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func (e *Executor) getLAPIClient(ctx context.Context) (*apiclient.ApiClient, error) {
	client, err := apiclient.GetLAPIClient()
	if err == nil {
		return client, nil
	}

	if e.lapiCfg == nil {
		return nil, fmt.Errorf("lapi client not initialized and local_api_credentials is not configured")
	}

	if e.lapiCfg.Credentials == nil {
		if e.lapiCfg.CredentialsFilePath == "" {
			return nil, fmt.Errorf("local_api_credentials path is empty")
		}
		if err := e.lapiCfg.Load(); err != nil {
			return nil, fmt.Errorf("failed to load local_api_credentials: %w", err)
		}
	}

	creds := e.lapiCfg.Credentials
	if creds == nil || creds.URL == "" || creds.Login == "" || creds.Password == "" {
		return nil, fmt.Errorf("invalid local_api_credentials (missing url/login/password)")
	}

	if err := apiclient.InitLAPIClient(ctx, creds.URL, creds.PapiURL, creds.Login, creds.Password, nil); err != nil {
		return nil, fmt.Errorf("failed to init lapi client: %w", err)
	}

	client, err = apiclient.GetLAPIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get lapi client: %w", err)
	}

	return client, nil
}

func decisionReason(input string, login string) string {
	if input != "" {
		return input
	}
	if login != "" {
		return fmt.Sprintf("manual decision from %s", login)
	}
	return defaultDecisionScenario
}

func normalizeDuration(raw string) (string, error) {
	if raw == "" {
		return defaultDecisionDuration, nil
	}
	if _, err := time.ParseDuration(raw); err != nil {
		return "", fmt.Errorf("invalid duration: %w", err)
	}
	return raw, nil
}

func (e *Executor) retryLAPIOperation(ctx context.Context, opName string, fn func(context.Context) (*apiclient.Response, error)) error {
	maxRetries := envIntWithDefault(envLAPIRetryMax, defaultLAPIRetryMax)
	baseDelay := envDuration(envLAPIRetryBase, defaultLAPIRetryBase)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := fn(ctx)
		if err == nil {
			return nil
		}

		lastErr = err
		status := 0
		if resp != nil && resp.Response != nil {
			status = resp.Response.StatusCode
		}

		shouldRetry := status >= 500 || status == 0
		if !shouldRetry || attempt == maxRetries {
			return fmt.Errorf("%s failed: %w", opName, lastErr)
		}

		delay := baseDelay * time.Duration(1<<attempt)
		e.logger.WithFields(log.Fields{
			"op":      opName,
			"attempt": attempt + 1,
			"status":  status,
			"delay":   delay.String(),
		}).Warn("lapi request failed, will retry")

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s canceled: %w", opName, ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("%s failed: %w", opName, lastErr)
}

func buildAlertForDecision(scope string, value string, decisionType string, duration string, reason string, origin string) *models.Alert {
	capacity := int32(0)
	leakSpeed := "0"
	eventsCount := int32(1)
	empty := ""
	simulated := false
	startAt := time.Now().UTC().Format(time.RFC3339)
	stopAt := startAt
	createdAt := startAt

	decision := models.Decision{
		Duration: &duration,
		Scope:    &scope,
		Value:    &value,
		Type:     &decisionType,
		Scenario: &reason,
		Origin:   &origin,
	}

	source := &models.Source{
		Scope: &scope,
		Value: &value,
	}
	if scope == types.Ip {
		source.IP = value
	} else if scope == types.Range {
		source.Range = value
	}

	alert := models.Alert{
		Capacity:        &capacity,
		Decisions:       []*models.Decision{&decision},
		Events:          []*models.Event{},
		EventsCount:     &eventsCount,
		Leakspeed:       &leakSpeed,
		Message:         &reason,
		ScenarioHash:    &empty,
		Scenario:        &reason,
		ScenarioVersion: &empty,
		Simulated:       &simulated,
		Source:          source,
		StartAt:         &startAt,
		StopAt:          &stopAt,
		CreatedAt:       createdAt,
		Remediation:     true,
	}

	return &alert
}

func (e *Executor) executeAddWhitelist(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p WhitelistParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid whitelist params: %w", err)
	}

	value := p.IP
	scope := types.Ip
	if p.CIDR != "" {
		value = p.CIDR
		scope = types.Range
	}

	if value == "" {
		return nil, fmt.Errorf("ip or cidr required")
	}

	client, err := e.getLAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	duration, err := normalizeDuration(p.Duration)
	if err != nil {
		return nil, err
	}

	reason := decisionReason(p.Reason, "")
	if e.lapiCfg != nil && e.lapiCfg.Credentials != nil {
		reason = decisionReason(p.Reason, e.lapiCfg.Credentials.Login)
	}

	alert := buildAlertForDecision(scope, value, "whitelist", duration, reason, types.CscliOrigin)
	alerts := models.AddAlertsRequest{alert}

	if err := e.retryLAPIOperation(ctx, "add whitelist decision", func(reqCtx context.Context) (*apiclient.Response, error) {
		_, resp, err := client.Alerts.Add(reqCtx, alerts)
		return resp, err
	}); err != nil {
		return nil, err
	}

	e.logger.WithFields(log.Fields{
		"value":    value,
		"scope":    scope,
		"duration": duration,
	}).Info("whitelist decision added via LAPI")

	return map[string]interface{}{
		"status":   "created",
		"value":    value,
		"scope":    scope,
		"type":     "whitelist",
		"duration": duration,
	}, nil
}

func (e *Executor) executeRemoveWhitelist(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p WhitelistParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid whitelist params: %w", err)
	}

	value := p.IP
	scope := types.Ip
	if p.CIDR != "" {
		value = p.CIDR
		scope = types.Range
	}

	if value == "" {
		return nil, fmt.Errorf("ip or cidr required")
	}

	client, err := e.getLAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	var resp *models.DeleteDecisionResponse
	if err := e.retryLAPIOperation(ctx, "remove whitelist decision", func(reqCtx context.Context) (*apiclient.Response, error) {
		var err error
		var apiResp *apiclient.Response
		resp, apiResp, err = client.Decisions.Delete(reqCtx, apiclient.DecisionsDeleteOpts{
			ScopeEquals: scope,
			ValueEquals: value,
			TypeEquals:  "whitelist",
		})
		return apiResp, err
	}); err != nil {
		return nil, err
	}

	e.logger.WithFields(log.Fields{
		"value":   value,
		"scope":   scope,
		"deleted": resp.NbDeleted,
	}).Info("whitelist decision removed via LAPI")

	return map[string]interface{}{
		"deleted": resp.NbDeleted,
	}, nil
}

func (e *Executor) executeAddDecision(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p DecisionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid decision params: %w", err)
	}

	if p.Value == "" || p.Scope == "" || p.Type == "" {
		return nil, fmt.Errorf("value, scope, and type are required")
	}

	p.Scope = types.NormalizeScope(p.Scope)

	client, err := e.getLAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	duration, err := normalizeDuration(p.Duration)
	if err != nil {
		return nil, err
	}

	reason := decisionReason(p.Reason, "")
	if e.lapiCfg != nil && e.lapiCfg.Credentials != nil {
		reason = decisionReason(p.Reason, e.lapiCfg.Credentials.Login)
	}

	alert := buildAlertForDecision(p.Scope, p.Value, p.Type, duration, reason, types.CscliOrigin)
	alerts := models.AddAlertsRequest{alert}

	if err := e.retryLAPIOperation(ctx, "add decision", func(reqCtx context.Context) (*apiclient.Response, error) {
		_, resp, err := client.Alerts.Add(reqCtx, alerts)
		return resp, err
	}); err != nil {
		return nil, err
	}

	e.logger.WithFields(log.Fields{
		"value":    p.Value,
		"scope":    p.Scope,
		"type":     p.Type,
		"duration": duration,
	}).Info("decision added via LAPI")

	return map[string]interface{}{
		"status":   "created",
		"value":    p.Value,
		"scope":    p.Scope,
		"type":     p.Type,
		"duration": duration,
	}, nil
}

func (e *Executor) executeRemoveDecision(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p DecisionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid decision params: %w", err)
	}

	if p.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	client, err := e.getLAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	if p.Scope != "" {
		p.Scope = types.NormalizeScope(p.Scope)
	}

	opts := apiclient.DecisionsDeleteOpts{
		ValueEquals: p.Value,
	}
	if p.Scope != "" {
		opts.ScopeEquals = p.Scope
	}
	if p.Type != "" {
		opts.TypeEquals = p.Type
	}

	var resp *models.DeleteDecisionResponse
	if err := e.retryLAPIOperation(ctx, "remove decision", func(reqCtx context.Context) (*apiclient.Response, error) {
		var err error
		var apiResp *apiclient.Response
		resp, apiResp, err = client.Decisions.Delete(reqCtx, opts)
		return apiResp, err
	}); err != nil {
		return nil, err
	}

	e.logger.WithFields(log.Fields{
		"value":   p.Value,
		"scope":   p.Scope,
		"type":    p.Type,
		"deleted": resp.NbDeleted,
	}).Info("decision removed via LAPI")

	return map[string]interface{}{
		"deleted": resp.NbDeleted,
	}, nil
}

func (e *Executor) executePing(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{
		"pong":      true,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (e *Executor) executeForceSync(ctx context.Context) (interface{}, error) {
	// 该指令应触发立即同步
	// 目前仅返回确认，实际实现需通知 pusher 触发同步
	e.logger.Info("force sync requested")
	return map[string]interface{}{
		"acknowledged": true,
		"note":         "sync will be triggered on next cycle",
	}, nil
}

// ConfigUpdateParams 为配置更新指令参数
type ConfigUpdateParams struct {
	Version string `json:"version"`
	Config  []byte `json:"config"`
}

func (e *Executor) executeUpdateConfig(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p ConfigUpdateParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid config update params: %w", err)
	}

	e.logger.WithFields(log.Fields{
		"version": p.Version,
		"size":    len(p.Config),
	}).Info("config update requested")

	// TODO: 实现真实配置更新逻辑
	// 1. 校验新配置
	// 2. 写入配置文件
	// 3. 触发 reload

	return map[string]interface{}{
		"acknowledged": true,
		"version":      p.Version,
		"note":         "config update requires manual implementation",
	}, nil
}

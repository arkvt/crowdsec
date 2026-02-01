package database

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
)

// PusherAlert represents a simplified alert for pusher sync
type PusherAlert struct {
	ID           int    `json:"id"`
	UUID         string `json:"uuid,omitempty"`
	Scenario     string `json:"scenario,omitempty"`
	Message      string `json:"message,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	SourceScope  string `json:"source_scope,omitempty"`
	SourceValue  string `json:"source_value,omitempty"`
	Capacity     int    `json:"capacity,omitempty"`
	LeakSpeed    string `json:"leak_speed,omitempty"`
	ScenarioHash string `json:"scenario_hash,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	StoppedAt    string `json:"stopped_at,omitempty"`
	EventsCount  int    `json:"events_count,omitempty"`
	Simulated    bool   `json:"simulated,omitempty"`
}

// PusherDecision represents a simplified decision for pusher sync
type PusherDecision struct {
	ID        int    `json:"id"`
	UUID      string `json:"uuid,omitempty"`
	Value     string `json:"value,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Type      string `json:"type,omitempty"`
	Origin    string `json:"origin,omitempty"`
	Scenario  string `json:"scenario,omitempty"`
	Until     string `json:"until,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	Simulated bool   `json:"simulated,omitempty"`
}

// QueryAlertsAfterID queries alerts with ID greater than lastID, limited to batchSize
func (c *Client) QueryAlertsAfterID(ctx context.Context, lastID int, batchSize int) ([]*PusherAlert, error) {
	alerts, err := c.Ent.Alert.Query().
		Where(alert.IDGT(lastID)).
		Order(ent.Asc(alert.FieldID)).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*PusherAlert, len(alerts))
	for i, a := range alerts {
		result[i] = &PusherAlert{
			ID:           a.ID,
			UUID:         a.UUID,
			Scenario:     a.Scenario,
			Message:      a.Message,
			SourceIP:     a.SourceIp,
			SourceScope:  a.SourceScope,
			SourceValue:  a.SourceValue,
			Capacity:     int(a.Capacity),
			LeakSpeed:    a.LeakSpeed,
			ScenarioHash: a.ScenarioHash,
			CreatedAt:    a.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:    a.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			StartedAt:    a.StartedAt.Format("2006-01-02T15:04:05Z"),
			StoppedAt:    a.StoppedAt.Format("2006-01-02T15:04:05Z"),
			EventsCount:  int(a.EventsCount),
			Simulated:    a.Simulated,
		}
	}

	return result, nil
}

// QueryDecisionsAfterID queries decisions with ID greater than lastID, limited to batchSize
func (c *Client) QueryDecisionsAfterID(ctx context.Context, lastID int, batchSize int) ([]*PusherDecision, error) {
	decisions, err := c.Ent.Decision.Query().
		Where(decision.IDGT(lastID)).
		Order(ent.Asc(decision.FieldID)).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*PusherDecision, len(decisions))
	for i, d := range decisions {
		var until string
		if d.Until != nil {
			until = d.Until.Format("2006-01-02T15:04:05Z")
		}
		result[i] = &PusherDecision{
			ID:        d.ID,
			UUID:      d.UUID,
			Value:     d.Value,
			Scope:     d.Scope,
			Type:      d.Type,
			Origin:    d.Origin,
			Scenario:  d.Scenario,
			Until:     until,
			CreatedAt: d.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Simulated: d.Simulated,
		}
	}

	return result, nil
}

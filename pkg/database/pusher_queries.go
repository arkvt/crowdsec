package database

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
)

// PusherAlert represents a simplified alert for pusher sync
type PusherAlert struct {
	ID              int     `json:"id"`
	UUID            string  `json:"uuid,omitempty"`
	Scenario        string  `json:"scenario,omitempty"`
	BucketID        string  `json:"bucket_id,omitempty"`
	Message         string  `json:"message,omitempty"`
	EventsCount     int     `json:"events_count,omitempty"`
	StartedAt       string  `json:"started_at,omitempty"`
	StoppedAt       string  `json:"stopped_at,omitempty"`
	SourceIP        string  `json:"source_ip,omitempty"`
	SourceRange     string  `json:"source_range,omitempty"`
	SourceASNumber  string  `json:"source_as_number,omitempty"`
	SourceASName    string  `json:"source_as_name,omitempty"`
	SourceCountry   string  `json:"source_country,omitempty"`
	SourceLatitude  float32 `json:"source_latitude,omitempty"`
	SourceLongitude float32 `json:"source_longitude,omitempty"`
	SourceScope     string  `json:"source_scope,omitempty"`
	SourceValue     string  `json:"source_value,omitempty"`
	Capacity        int     `json:"capacity,omitempty"`
	LeakSpeed       string  `json:"leak_speed,omitempty"`
	ScenarioVersion string  `json:"scenario_version,omitempty"`
	ScenarioHash    string  `json:"scenario_hash,omitempty"`
	CreatedAt       string  `json:"created_at,omitempty"`
	UpdatedAt       string  `json:"updated_at,omitempty"`
	Simulated       bool    `json:"simulated,omitempty"`
	Remediation     bool    `json:"remediation,omitempty"`
	MachineAlerts   int     `json:"machine_alerts,omitempty"`
}

// PusherDecision represents a simplified decision for pusher sync
type PusherDecision struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	Until          string `json:"until,omitempty"`
	Scenario       string `json:"scenario,omitempty"`
	Type           string `json:"type,omitempty"`
	StartIP        int64  `json:"start_ip,omitempty"`
	EndIP          int64  `json:"end_ip,omitempty"`
	StartSuffix    int64  `json:"start_suffix,omitempty"`
	EndSuffix      int64  `json:"end_suffix,omitempty"`
	IPSize         int64  `json:"ip_size,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Value          string `json:"value,omitempty"`
	Origin         string `json:"origin,omitempty"`
	Simulated      bool   `json:"simulated,omitempty"`
	AlertDecisions int    `json:"alert_decisions,omitempty"`
}

// QueryAlertsAfterID queries alerts with ID greater than lastID, limited to batchSize
func (c *Client) QueryAlertsAfterID(ctx context.Context, lastID int, batchSize int) ([]*PusherAlert, error) {
	alerts, err := c.Ent.Alert.Query().
		Where(alert.IDGT(lastID)).
		WithOwner(func(q *ent.MachineQuery) {
			q.Select(machine.FieldID)
		}).
		Order(ent.Asc(alert.FieldID)).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*PusherAlert, len(alerts))
	for i, a := range alerts {
		result[i] = &PusherAlert{
			ID:              a.ID,
			UUID:            a.UUID,
			Scenario:        a.Scenario,
			BucketID:        a.BucketId,
			Message:         a.Message,
			EventsCount:     int(a.EventsCount),
			StartedAt:       a.StartedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			StoppedAt:       a.StoppedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			SourceIP:        a.SourceIp,
			SourceRange:     a.SourceRange,
			SourceASNumber:  a.SourceAsNumber,
			SourceASName:    a.SourceAsName,
			SourceCountry:   a.SourceCountry,
			SourceLatitude:  a.SourceLatitude,
			SourceLongitude: a.SourceLongitude,
			SourceScope:     a.SourceScope,
			SourceValue:     a.SourceValue,
			Capacity:        int(a.Capacity),
			LeakSpeed:       a.LeakSpeed,
			ScenarioVersion: a.ScenarioVersion,
			ScenarioHash:    a.ScenarioHash,
			CreatedAt:       a.CreatedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			UpdatedAt:       a.UpdatedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			Simulated:       a.Simulated,
			Remediation:     a.Remediation,
		}
		if a.Edges.Owner != nil {
			result[i].MachineAlerts = a.Edges.Owner.ID
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
			until = d.Until.Format("2006-01-02 15:04:05.000000000 -0700 MST")
		}
		result[i] = &PusherDecision{
			ID:             d.ID,
			UUID:           d.UUID,
			CreatedAt:      d.CreatedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			UpdatedAt:      d.UpdatedAt.Format("2006-01-02 15:04:05.000000000 -0700 MST"),
			Until:          until,
			Scenario:       d.Scenario,
			Type:           d.Type,
			StartIP:        d.StartIP,
			EndIP:          d.EndIP,
			StartSuffix:    d.StartSuffix,
			EndSuffix:      d.EndSuffix,
			IPSize:         d.IPSize,
			Scope:          d.Scope,
			Value:          d.Value,
			Origin:         d.Origin,
			Simulated:      d.Simulated,
			AlertDecisions: d.AlertDecisions,
		}
	}

	return result, nil
}

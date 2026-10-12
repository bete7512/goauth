package gorm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
	"time"
)

type outboxRow struct {
	ID          string `gorm:"primaryKey"`
	Envelope    string
	Attempts    int
	LeaseID     string
	AvailableAt time.Time
	CreatedAt   time.Time
}

func (outboxRow) TableName() string { return "goauth_outbox" }

func (s *GormStorage) AppendEvent(ctx context.Context, event types.EventEnvelope) error {
	if _, err := event.Event(); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(encoded) > 1<<20 {
		return fmt.Errorf("outbox event exceeds 1 MiB")
	}
	return s.db.WithContext(ctx).Create(&outboxRow{ID: event.ID, Envelope: string(encoded), CreatedAt: time.Now().UTC(), AvailableAt: time.Now().UTC()}).Error
}

func (s *GormStorage) ClaimEvents(ctx context.Context, leaseID string, limit int, duration time.Duration) ([]types.OutboxEvent, error) {
	if leaseID == "" || limit < 1 || limit > 100 || duration <= 0 {
		return nil, fmt.Errorf("invalid outbox lease")
	}
	now := time.Now().UTC()
	var rows []outboxRow
	if err := s.db.WithContext(ctx).Where("available_at <= ?", now).Order("created_at, id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	claimed := make([]types.OutboxEvent, 0, len(rows))
	for _, row := range rows {
		result := s.db.WithContext(ctx).Model(&outboxRow{}).Where("id = ? AND available_at <= ?", row.ID, now).Updates(map[string]interface{}{"lease_id": leaseID, "available_at": now.Add(duration), "attempts": gorm.Expr("attempts + 1")})
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected != 1 {
			continue
		}
		var envelope types.EventEnvelope
		if err := json.Unmarshal([]byte(row.Envelope), &envelope); err != nil {
			return nil, err
		}
		claimed = append(claimed, types.OutboxEvent{Envelope: envelope, Attempts: row.Attempts + 1})
	}
	return claimed, nil
}

func (s *GormStorage) AckEvent(ctx context.Context, id, leaseID string) error {
	result := s.db.WithContext(ctx).Where("id = ? AND lease_id = ?", id, leaseID).Delete(&outboxRow{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (s *GormStorage) RetryEvent(ctx context.Context, id, leaseID string, next time.Time) error {
	result := s.db.WithContext(ctx).Model(&outboxRow{}).Where("id = ? AND lease_id = ?", id, leaseID).Updates(map[string]interface{}{"lease_id": "", "available_at": next.UTC()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

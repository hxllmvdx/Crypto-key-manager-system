package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hxllmvdx/Crypto-key-management-system/pkg/domain"
	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/kmserrors"
	"gorm.io/gorm"
)

type KeyRepository interface {
	// use in rpc
	Create(ctx context.Context, key *domain.Key) error
	GetByID(ctx context.Context, userID, keyID string) (*domain.Key, error)
	List(ctx context.Context, userID string) ([]domain.Key, error)
	Rotate(ctx context.Context, oldKey *domain.Key, newKey *domain.Key) error
	Disable(ctx context.Context, userID, keyID string, timeNow time.Time) error
	Destroy(ctx context.Context, userID, keyID string) error
	Restore(ctx context.Context, userID, keyID string) error

	// use in background handler
	ListEnabledThatExpired(ctx context.Context, timeNow time.Time) ([]domain.Key, error)
	DeleteOldDisabled(ctx context.Context, timeNow time.Time) error
}

type KeyRepo struct {
	db *gorm.DB
}

func NewKeyRepository(db *gorm.DB) KeyRepository {
	return &KeyRepo{db: db}
}

func (r *KeyRepo) Create(ctx context.Context, key *domain.Key) error {
	return r.db.WithContext(ctx).Create(key).Error
}

func (r *KeyRepo) GetByID(ctx context.Context, userID, keyID string) (*domain.Key, error) {
	var key domain.Key
	result := r.db.WithContext(ctx).
		Where("user_id = ? and id = ? AND status = ?", userID, keyID, commonv1.KeyStatus_KEY_STATUS_ENABLED).
		Order("version DESC").
		First(&key)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("get key: %w", kmserrors.ErrNotFound)
		}
		return nil, result.Error
	}

	return &key, nil
}

func (r *KeyRepo) List(ctx context.Context, userID string) ([]domain.Key, error) {
	var keys []domain.Key
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&keys).
		Error
	return keys, err
}

func (r *KeyRepo) Rotate(ctx context.Context, oldKey *domain.Key, newKey *domain.Key) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(newKey).Error; err != nil {
			return err
		}
		return tx.Model(&domain.Key{}).
			Where("id = ? AND version = ?", oldKey.ID, oldKey.Version).
			Updates(map[string]any{
				"status":     oldKey.Status,
				"updated_at": oldKey.UpdatedAt,
			}).Error
	})
}

func (r *KeyRepo) Disable(ctx context.Context, userID, keyID string, timeNow time.Time) error {
	return r.db.WithContext(ctx).
		Where("user_id = ? AND id = ?", userID, keyID).
		Updates(map[string]any{
			"disabled_at": timeNow,
		}).
		Error
}

func (r *KeyRepo) Destroy(ctx context.Context, userID, keyID string) error {
	return r.db.WithContext(ctx).
		Delete(&domain.Key{}, "user_id = ? AND id = ?", userID, keyID).
		Error
}

func (r *KeyRepo) Restore(ctx context.Context, userID, keyID string) error {
	return r.db.WithContext(ctx).
		Where("user_id = ? AND id = ?", userID, keyID).
		Updates(map[string]any{
			"disabled_at": nil,
		}).
		Error
}

func (r *KeyRepo) ListEnabledThatExpired(ctx context.Context, timeNow time.Time) ([]domain.Key, error) {
	var keys []domain.Key
	err := r.db.WithContext(ctx).
		Where("status = ? AND expiry_at <= ?", commonv1.KeyStatus_KEY_STATUS_ENABLED, timeNow).
		Find(&keys).
		Error
	return keys, err
}

func (r *KeyRepo) DeleteOldDisabled(ctx context.Context, timeNow time.Time) error {
	return r.db.WithContext(ctx).
		Delete(&domain.Key{}, "status = ? AND deleted_at is not NULL AND deleted_at >= ?",
			commonv1.KeyStatus_KEY_STATUS_DISABLED,
			timeNow.AddDate(0, -1, 0)).
		Error
}

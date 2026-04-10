package repository

import (
	"context"
	"errors"
	"fmt"
	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/domain"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/kmserrors"
	"gorm.io/gorm"
	"time"
)

type KeyRepository interface {
	Create(ctx context.Context, key *domain.Key) error
	GetByID(ctx context.Context, id string) (*domain.Key, error)
	List(ctx context.Context) ([]domain.Key, error)
	Update(ctx context.Context, key *domain.Key) error
	Rotate(ctx context.Context, oldKey *domain.Key, newKey *domain.Key) error
	ListEnabledKeysThatExpired(ctx context.Context, timeNow time.Time) ([]domain.Key, error)
	Disable(ctx context.Context, key *domain.Key, timeNow time.Time) error
	Destroy(ctx context.Context, key *domain.Key) error
	Restore(ctx context.Context, key *domain.Key) error
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

func (r *KeyRepo) GetByID(ctx context.Context, id string) (*domain.Key, error) {
	var key domain.Key
	result := r.db.WithContext(ctx).
		Where("id = ? AND status = ?", id, commonv1.KeyStatus_KEY_STATUS_ENABLED).
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

func (r *KeyRepo) List(ctx context.Context) ([]domain.Key, error) {
	var keys []domain.Key
	err := r.db.WithContext(ctx).Find(&keys).Error
	return keys, err
}

func (r *KeyRepo) Update(ctx context.Context, key *domain.Key) error {
	return r.db.WithContext(ctx).
		Model(&domain.Key{}).
		Where("id = ? AND version = ?", key.ID, key.Version).
		Updates(map[string]any{
			"status":     key.Status,
			"updated_at": key.UpdatedAt,
		}).Error
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

func (r *KeyRepo) ListEnabledKeysThatExpired(ctx context.Context, timeNow time.Time) ([]domain.Key, error) {
	var keys []domain.Key
	err := r.db.WithContext(ctx).
		Where("status = ? AND expiry_at <= ?", commonv1.KeyStatus_KEY_STATUS_ENABLED, timeNow).
		Find(&keys).
		Error
	return keys, err
}

func (r *KeyRepo) Disable(ctx context.Context, key *domain.Key, timeNow time.Time) error {
	return r.db.WithContext(ctx).
		Where("id = ?", key.ID).
		Updates(map[string]any{
			"disabled_at": timeNow,
		}).
		Error
}

func (r *KeyRepo) Destroy(ctx context.Context, key *domain.Key) error {
	return r.db.WithContext(ctx).
		Delete(&domain.Key{}, "id = ?", key.ID).
		Error
}

func (r *KeyRepo) Restore(ctx context.Context, key *domain.Key) error {
	return r.db.WithContext(ctx).
		Where("id = ?", key.ID).
		Updates(map[string]any{
			"disabled_at": nil,
		}).
		Error
}

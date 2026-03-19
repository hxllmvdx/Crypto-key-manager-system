package repository

import (
	"context"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/domain"
	"gorm.io/gorm"
)

type KeyRepository interface {
	Create(ctx context.Context, key *domain.Key) error
	GetByID(ctx context.Context, id string) (*domain.Key, error)
	List(ctx context.Context) ([]domain.Key, error)
	Update(ctx context.Context, key *domain.Key) error
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
	result := r.db.WithContext(ctx).Where("id = ?", id).Order("version DESC").First(&key)

	if result.Error == gorm.ErrRecordNotFound {
		return nil, gorm.ErrRecordNotFound
	}
	if result.Error != nil {
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
	return r.db.WithContext(ctx).Model(key).Updates(key).Error
}

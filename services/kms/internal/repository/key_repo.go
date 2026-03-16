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
}

type keyRepo struct {
	db *gorm.DB
}

func NewKeyRepository(db *gorm.DB) KeyRepository {
	return &keyRepo{db: db}
}

func (r *keyRepo) Create(ctx context.Context, key *domain.Key) error {
	return r.db.WithContext(ctx).Create(key).Error
}

func (r *keyRepo) GetByID(ctx context.Context, id string) (*domain.Key, error) {
	var key domain.Key
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&key).Error
	return &key, err
}

func (r *keyRepo) List(ctx context.Context) ([]domain.Key, error) {
	var keys []domain.Key
	err := r.db.WithContext(ctx).Find(&keys).Error
	return keys, err
}

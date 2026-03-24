package service

import (
	"context"
	"errors"
	"time"

	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/domain"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/repository"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/uuid"
)

type KeyService struct {
	repo repository.KeyRepository
}

func NewKeyService(repo repository.KeyRepository) *KeyService {
	return &KeyService{repo: repo}
}

func GenerateKeyMaterial(keyType commonv1.KeyType) ([]byte, error) {
	var (
		keyMaterial []byte
		err         error
	)

	switch keyType {
	case commonv1.KeyType_KEY_TYPE_AES_128:
		keyMaterial = make([]byte, 16)
		if _, err = rand.Read(keyMaterial); err != nil {
			return nil, err
		}
	case commonv1.KeyType_KEY_TYPE_AES_256:
		keyMaterial = make([]byte, 32)
		if _, err = rand.Read(keyMaterial); err != nil {
			return nil, err
		}
	case commonv1.KeyType_KEY_TYPE_RSA_2048:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keyMaterial = x509.MarshalPKCS1PrivateKey(privateKey)
	default:
		return nil, errors.New("unsupported key type")
	}

	return keyMaterial, nil
}

func (s *KeyService) GenerateKey(ctx context.Context, keyType commonv1.KeyType) (*domain.Key, error) {
	keyMaterial, err := GenerateKeyMaterial(keyType)
	if err != nil {
		return nil, err
	}

	algorithm := domain.KeyTypeToString(keyType)

	key := &domain.Key{
		ID:           uuid.New().String(),
		Version:      1,
		Algorithm:    algorithm,
		EncryptedKey: keyMaterial,
		Status:       "ENABLED",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = s.repo.Create(ctx, key)
	return key, err
}

func (s *KeyService) GetKey(ctx context.Context, id string) (*domain.Key, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *KeyService) ListKeys(ctx context.Context) ([]domain.Key, error) {
	return s.repo.List(ctx)
}

func (s *KeyService) RotateKey(ctx context.Context, keyID string, keyType commonv1.KeyType) (*domain.Key, error) {
	if keyID == "" {
		return nil, errors.New("keyID is empty")
	}

	oldKey, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if oldKey == nil {
		return nil, errors.New("key not found")
	}

	if oldKey.KeyStatus() == commonv1.KeyStatus_KEY_STATUS_DESTROYED {
		return nil, errors.New("key is destroyed")
	}

	keyMaterial, err := GenerateKeyMaterial(keyType)
	if err != nil {
		return nil, err
	}

	newKey := &domain.Key{
		ID:           oldKey.ID,
		Version:      oldKey.Version + 1,
		Algorithm:    oldKey.Algorithm,
		EncryptedKey: keyMaterial,
		Status:       "ENABLED",
		CreatedAt:    oldKey.CreatedAt,
		UpdatedAt:    time.Now(),
	}

	oldKey.Status = "DISABLED"
	if err := s.repo.Update(ctx, oldKey); err != nil {
		return nil, err
	}

	if err := s.repo.Create(ctx, newKey); err != nil {
		return nil, err
	}

	if newKey == nil {
		return nil, errors.New("failed to create new key")
	}

	return newKey, nil
}

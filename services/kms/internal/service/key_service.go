package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/kmserrors"
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

func isExpired(expiryAt, now time.Time) bool {
	return !expiryAt.After(now)
}

func isKeyRotatable(key *domain.Key, allowedStatusesForRotation map[commonv1.KeyStatus]struct{}) error {
	if key == nil {
		return errors.New("key is nil")
	}
	if key.ID == "" {
		return errors.New("keyID is empty")
	}
	if key.KeyType() == commonv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return errors.New("key type is unspecified")
	}
	if _, ok := allowedStatusesForRotation[key.Status]; !ok {
		return fmt.Errorf("%w: status=%s", kmserrors.ErrNotRotatable, key.Status.String())
	}
	return nil
}

func generateKeyMaterial(keyType commonv1.KeyType) ([]byte, error) {
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

func (s *KeyService) rotateOldKey(
	ctx context.Context,
	oldKey *domain.Key,
	statusForOldKeyAfterRotation commonv1.KeyStatus,
	allowedStatusesForRotation map[commonv1.KeyStatus]struct{},
	timeNow time.Time,
) (*domain.Key, error) {
	err := isKeyRotatable(oldKey, allowedStatusesForRotation)
	if err != nil {

		return nil, err
	}

	keyMaterial, err := generateKeyMaterial(oldKey.KeyType())
	if err != nil {
		return nil, err
	}

	newKey := &domain.Key{
		ID:           oldKey.ID,
		Version:      oldKey.Version + 1,
		Algorithm:    oldKey.Algorithm,
		EncryptedKey: keyMaterial,
		Status:       commonv1.KeyStatus_KEY_STATUS_ENABLED,
		CreatedAt:    oldKey.CreatedAt,
		UpdatedAt:    timeNow,
		ExpiryAt:     timeNow.AddDate(0, 1, 0),
		DisabledAt:   oldKey.DisabledAt,
	}

	oldKey.Status = statusForOldKeyAfterRotation
	oldKey.UpdatedAt = timeNow

	if err := s.repo.Rotate(ctx, oldKey, newKey); err != nil {
		return nil, err
	}

	if newKey == nil {
		return nil, errors.New("failed to create new key")
	}

	return newKey, nil
}

func NewKeyService(repo repository.KeyRepository) *KeyService {
	return &KeyService{repo: repo}
}

func (s *KeyService) GenerateKey(ctx context.Context, keyType commonv1.KeyType, timeNow time.Time) (*domain.Key, error) {
	keyMaterial, err := generateKeyMaterial(keyType)
	if err != nil {
		return nil, err
	}

	algorithm := domain.KeyTypeToString(keyType)

	key := &domain.Key{
		ID:           uuid.New().String(),
		Version:      1,
		Algorithm:    algorithm,
		EncryptedKey: keyMaterial,
		Status:       commonv1.KeyStatus_KEY_STATUS_ENABLED,
		CreatedAt:    timeNow,
		UpdatedAt:    timeNow,
		ExpiryAt:     timeNow.AddDate(0, 1, 0),
		DisabledAt:   time.Time{},
	}

	err = s.repo.Create(ctx, key)
	return key, err
}

func (s *KeyService) GetKeyOrRotateIfExpired(ctx context.Context, keyID string, timeNow time.Time) (*domain.Key, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: key id is empty", kmserrors.ErrInvalidArgument)
	}

	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if !isExpired(key.ExpiryAt, timeNow) {
		return key, nil
	}

	key.Status = commonv1.KeyStatus_KEY_STATUS_PENDING_ROTATION

	allowedStatusesForRotation := map[commonv1.KeyStatus]struct{}{
		commonv1.KeyStatus_KEY_STATUS_ENABLED:          {},
		commonv1.KeyStatus_KEY_STATUS_PENDING_ROTATION: {},
	}

	return s.rotateOldKey(
		ctx,
		key,
		commonv1.KeyStatus_KEY_STATUS_EXPIRED,
		allowedStatusesForRotation,
		timeNow,
	)
}

func (s *KeyService) ListKeys(ctx context.Context) ([]domain.Key, error) {
	return s.repo.List(ctx)
}

func (s *KeyService) RotateKey(ctx context.Context, keyID string, timeNow time.Time) (*domain.Key, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: key id is empty", kmserrors.ErrInvalidArgument)
	}

	oldKey, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	allowedStatusesForRotation := map[commonv1.KeyStatus]struct{}{
		commonv1.KeyStatus_KEY_STATUS_ENABLED: {},
	}

	return s.rotateOldKey(
		ctx,
		oldKey,
		commonv1.KeyStatus_KEY_STATUS_ROTATED,
		allowedStatusesForRotation,
		timeNow,
	)
}

func (s *KeyService) RotateEnabledKeysThatExpired(ctx context.Context, timeNow time.Time) ([]domain.Key, error) {
	keys, err := s.repo.ListEnabledKeysThatExpired(ctx, timeNow)
	if err != nil {
		return nil, err
	}

	allowedStatusesForRotation := map[commonv1.KeyStatus]struct{}{
		commonv1.KeyStatus_KEY_STATUS_ENABLED: {},
	}

	newKeys := make([]domain.Key, 0, len(keys))
	for _, key := range keys {
		newKey, err := s.rotateOldKey(
			ctx,
			&key,
			commonv1.KeyStatus_KEY_STATUS_EXPIRED,
			allowedStatusesForRotation,
			timeNow,
		)

		if err != nil {
			return nil, err
		}

		newKeys = append(newKeys, *newKey)
	}

	return newKeys, nil
}

func (s *KeyService) DisableKey(ctx context.Context, keyID string, timeNow time.Time) error {
	if keyID == "" {
		return fmt.Errorf("%w: key id is empty", kmserrors.ErrInvalidArgument)
	}

	err := s.repo.Disable(ctx, keyID, timeNow)
	if err != nil {
		return err
	}

	return nil
}

func (s *KeyService) DestroyKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("%w: key id is empty", kmserrors.ErrInvalidArgument)
	}

	err := s.repo.Destroy(ctx, keyID)
	if err != nil {
		return err
	}

	return nil
}

func (s *KeyService) RestoreKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("%w: key id is empty", kmserrors.ErrInvalidArgument)
	}

	err := s.repo.Restore(ctx, keyID)
	if err != nil {
		return err
	}

	return nil
}

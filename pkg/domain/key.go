package domain

import (
	"time"

	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Key struct {
	ID           string `gorm:"primary_key;size:36"`
	Version      uint32 `gorm:"primary_key"`
	OwnerID      User
	Algorithm    string
	EncryptedKey []byte
	Status       commonv1.KeyStatus `gorm:"type:int"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ExpiryAt     time.Time
	DisabledAt   time.Time
	UserID       string `gorm:"type:uuid;index;not null"`
}

func (key Key) KeyType() commonv1.KeyType {
	switch key.Algorithm {
	case "AES_128":
		return commonv1.KeyType_KEY_TYPE_AES_128
	case "AES_256":
		return commonv1.KeyType_KEY_TYPE_AES_256
	case "RSA_2048":
		return commonv1.KeyType_KEY_TYPE_RSA_2048
	default:
		return commonv1.KeyType_KEY_TYPE_UNSPECIFIED
	}
}

func KeyTypeToString(keyType commonv1.KeyType) string {
	switch keyType {
	case commonv1.KeyType_KEY_TYPE_AES_128:
		return "AES_128"
	case commonv1.KeyType_KEY_TYPE_AES_256:
		return "AES_256"
	case commonv1.KeyType_KEY_TYPE_RSA_2048:
		return "RSA_2048"
	default:
		return "UNSPECIFIED"
	}
}

func (key Key) KeyStatus() commonv1.KeyStatus { return key.Status }

func (key Key) KeyMetadata() *kmsv1.KeyMetadata {
	metadata := &kmsv1.KeyMetadata{
		KeyId:     key.ID,
		Version:   key.Version,
		Type:      key.KeyType(),
		CreatedAt: timestamppb.New(key.CreatedAt),
		UpdatedAt: timestamppb.New(key.UpdatedAt),
		Status:    key.Status,
	}

	return metadata
}

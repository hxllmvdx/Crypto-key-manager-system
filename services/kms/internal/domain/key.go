package domain

import (
	"time"

	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Key struct {
	ID           string `gorm:"primary_key;size:36"`
	Version      uint32
	Algorithm    string
	EncryptedKey []byte
	Status       string
	CreatedAt    time.Time
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

func (key Key) KeyStatus() commonv1.KeyStatus {
	switch key.Status {
	case "ENABLED":
		return commonv1.KeyStatus_KEY_STATUS_ENABLED
	case "DISABLED":
		return commonv1.KeyStatus_KEY_STATUS_DISABLED
	case "PENDING_ROTATION":
		return commonv1.KeyStatus_KEY_STATUS_PENDING_ROTATION
	case "PENDING_DEACTIVATION":
		return commonv1.KeyStatus_KEY_STATUS_PENDING_DEACTIVATION
	case "DESTROYED":
		return commonv1.KeyStatus_KEY_STATUS_DESTROYED
	case "EXPIRED":
		return commonv1.KeyStatus_KEY_STATUS_EXPIRED
	default:
		return commonv1.KeyStatus_KEY_STATUS_UNSPECIFIED
	}
}

func (key Key) KeyMetadata() *kmsv1.KeyMetadata {
	metadata := &kmsv1.KeyMetadata{
		KeyId:     key.ID,
		Version:   key.Version,
		Type:      key.KeyType(),
		CreatedAt: timestamppb.New(key.CreatedAt),
		Status:    key.KeyStatus(),
	}

	return metadata
}

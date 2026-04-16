package service

import (
	"context"

	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/client"
)

type ApiService interface {
	ListKeys(ctx context.Context, userId string) ([]string, error)
	GetKey(ctx context.Context, keyId, userId string) ([]byte, error)
	CreateKey(ctx context.Context, userId string) (string, error)
	RotateKey(ctx context.Context, keyId, userId string) (string, error)
	RestoreKey(ctx context.Context, keyId, userId string) error
	DisableKey(ctx context.Context, keyId, userId string) error
	DestroyKey(ctx context.Context, keyId, userId string) error
	Encrypt(ctx context.Context, keyId, userId string, plaintext []byte) ([]byte, []byte, error)
	Decrypt(ctx context.Context, keyId, userId string, ciphertext, nonceBytes []byte) ([]byte, error)
}

type apiService struct {
	kmsClient    *client.KMSClient
	cryptoClient *client.CryptoClient
}

func NewApiService(kmsClient *client.KMSClient, cryptoClient *client.CryptoClient) ApiService {
	return &apiService{
		kmsClient:    kmsClient,
		cryptoClient: cryptoClient,
	}
}

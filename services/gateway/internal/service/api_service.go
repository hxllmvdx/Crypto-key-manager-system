package service

import (
	"context"
	"errors"

	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/client"
)

type ApiService interface {
	ListKeys(ctx context.Context) ([]string, error)
	GetKey(ctx context.Context, keyId string) ([]byte, error)
	CreateKey(ctx context.Context) (string, error)
	RotateKey(ctx context.Context, keyId string) (string, error)
	RestoreKey(ctx context.Context, keyId string) error
	DisableKey(ctx context.Context, keyId string) error
	DestroyKey(ctx context.Context, keyId string) error
	Encrypt(ctx context.Context, keyId string, plaintext []byte) ([]byte, []byte, error)
	Decrypt(ctx context.Context, keyId string, ciphertext, nonceBytes []byte) ([]byte, error)
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

func (s *apiService) Encrypt(ctx context.Context, keyId string, plaintext []byte) ([]byte, []byte, error) {
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, nil, errors.New("user_id not found in context")
	}

	ciphertext, nonceBytes, err := s.cryptoClient.Encrypt(ctx, keyId, userID, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, nonceBytes, nil
}

func (s *apiService) Decrypt(ctx context.Context, keyId string, ciphertext, nonceBytes []byte) ([]byte, error) {
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return nil, errors.New("user_id not found in context")
	}

	plaintext, err := s.cryptoClient.Decrypt(ctx, keyId, userID, ciphertext, nonceBytes)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

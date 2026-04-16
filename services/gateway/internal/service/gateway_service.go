package service

import (
	"context"

	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/repository"
)

type AuthResult struct {
	AccessToken  string
	RefreshToken string
}

type GatewayService interface {
	UserLogin(ctx context.Context, userName, password string) (AuthResult, error)
	UserRegister(ctx context.Context, userName, password string) (AuthResult, error)
	UserRefresh(ctx context.Context, refreshToken string) (AuthResult, error)
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

type gatewayService struct {
	repo *repository.UserRepository
}

func NewGatewayService(repo *repository.UserRepository) GatewayService {
	return &gatewayService{
		repo: repo,
	}
}

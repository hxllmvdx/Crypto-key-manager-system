package client

import (
	"context"
	"time"

	crypto "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/crypto/v1"
	"google.golang.org/grpc"
)

type CryptoClient struct {
	client  crypto.CryptoServiceClient
	timeout time.Duration
}

func NewCryptoClient(conn *grpc.ClientConn, timeout time.Duration) *CryptoClient {
	return &CryptoClient{
		client:  crypto.NewCryptoServiceClient(conn),
		timeout: timeout,
	}
}

func (c *CryptoClient) Encrypt(ctx context.Context, keyId, userId string, plaintext []byte) ([]byte, []byte, error) {
	if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	resp, err := c.client.Encrypt(ctx, &crypto.EncryptRequest{
		KeyId:     keyId,
		UserId:    userId,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, nil, err
	}

	return resp.Ciphertext, resp.NonceBytes, nil
}

func (c *CryptoClient) Decrypt(ctx context.Context, keyId, userId string, ciphertext, nonceBytes []byte) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok && c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	resp, err := c.client.Decrypt(ctx, &crypto.DecryptRequest{
		KeyId:      keyId,
		UserId:     userId,
		Ciphertext: ciphertext,
		NonceBytes: nonceBytes,
	})
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}

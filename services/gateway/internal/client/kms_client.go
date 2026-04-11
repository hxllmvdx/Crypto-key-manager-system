package client

import (
	"context"
	"errors"
	"github.com/hxllmvdx/Crypto-key-management-system/pkg/domain"
	kms "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"google.golang.org/grpc"
	"io"
	"time"
)

type KMSClient struct {
	client  kms.KMSServiceClient
	timeout time.Duration
}

func (c *KMSClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

func NewKMSClient(conn *grpc.ClientConn, timeout time.Duration) *KMSClient {
	return &KMSClient{
		client:  kms.NewKMSServiceClient(conn),
		timeout: timeout,
	}
}

func (c *KMSClient) GenerateKey(ctx context.Context, userID, keyType string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.client.GenerateKey(ctx, &kms.GenerateKeyRequest{
		Type:   domain.StringToKeyType(keyType),
		UserId: userID,
	})
	if err != nil {
		return "", err
	}

	return resp.Metadata.KeyId, nil
}

func (c *KMSClient) GetKey(ctx context.Context, userID, keyID string) ([]byte, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.client.GetKey(ctx, &kms.GetKeyRequest{
		KeyId:  keyID,
		UserId: userID,
	})
	if err != nil {
		return nil, err
	}

	return resp.Key.KeyMaterial, nil
}

func (c *KMSClient) ListKeys(ctx context.Context, userID string) ([]string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	stream, err := c.client.ListKeys(ctx, &kms.ListKeysRequest{
		UserId: userID,
	})
	if err != nil {
		return nil, err
	}

	var keyIds []string
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		keyIds = append(keyIds, resp.Key.KeyId)
	}

	return keyIds, nil
}

func (c *KMSClient) RotateKey(ctx context.Context, userID, keyID string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.client.RotateKey(ctx, &kms.RotateKeyRequest{
		KeyId:  keyID,
		UserId: userID,
	})
	if err != nil {
		return "", err
	}

	return resp.Metadata.KeyId, nil
}

func (c *KMSClient) DisableKey(ctx context.Context, userID, keyID string) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	_, err := c.client.DisableKey(ctx, &kms.DisableKeyRequest{
		KeyId:  keyID,
		UserId: userID,
	})

	return err
}

func (c *KMSClient) DestroyKey(ctx context.Context, userID, keyID string) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	_, err := c.client.DestroyKey(ctx, &kms.DestroyKeyRequest{
		KeyId:  keyID,
		UserId: userID,
	})

	return err
}

func (c *KMSClient) RestoreKey(ctx context.Context, userID, keyID string) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	_, err := c.client.RestoreKey(ctx, &kms.RestoreKeyRequest{
		KeyId:  keyID,
		UserId: userID,
	})

	return err
}

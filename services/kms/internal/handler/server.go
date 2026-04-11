package handlerG

import (
	"context"
	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"time"
)

type KMSServer struct {
	kmsv1.UnimplementedKMSServiceServer
	repo *service.KeyService
}

func NewKMSServer(repo *service.KeyService) *KMSServer {
	return &KMSServer{
		repo: repo,
	}
}

func (server *KMSServer) GenerateKey(ctx context.Context, req *kmsv1.GenerateKeyRequest) (*kmsv1.GenerateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.Type == commonv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "key type has to be specified")
	}

	key, err := server.repo.GenerateKey(ctx, req.UserId, req.Type, time.Now().UTC())
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	metadata := key.KeyMetadata()

	return &kmsv1.GenerateKeyResponse{Metadata: metadata}, nil
}

func (server *KMSServer) GetKey(ctx context.Context, req *kmsv1.GetKeyRequest) (*kmsv1.GetKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	key, err := server.repo.GetKeyOrRotateIfExpired(ctx, req.UserId, req.KeyId, time.Now().UTC())
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	return &kmsv1.GetKeyResponse{
		Key: &kmsv1.Key{
			Metadata:    key.KeyMetadata(),
			KeyMaterial: key.EncryptedKey,
		},
	}, nil
}

func (server *KMSServer) ListKeys(req *kmsv1.ListKeysRequest, stream grpc.ServerStreamingServer[kmsv1.ListKeysResponse]) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return status.Error(codes.InvalidArgument, "user id is empty")
	}

	keys, err := server.repo.ListKeys(stream.Context(), req.UserId)
	if err != nil {
		return errorToGRPCError(err)
	}

	for _, key := range keys {
		response := &kmsv1.ListKeysResponse{
			Key: key.KeyMetadata(),
		}

		if err := stream.Send(response); err != nil {
			return errorToGRPCError(err)
		}
	}

	return nil
}

func (server *KMSServer) RotateKey(ctx context.Context, req *kmsv1.RotateKeyRequest) (*kmsv1.RotateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	key, err := server.repo.RotateKey(ctx, req.UserId, req.KeyId, time.Now().UTC())
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	return &kmsv1.RotateKeyResponse{Metadata: key.KeyMetadata()}, nil
}

func (server *KMSServer) DisableKey(ctx context.Context, req *kmsv1.DisableKeyRequest) (*kmsv1.DisableKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	err := server.repo.DisableKey(ctx, req.UserId, req.KeyId, time.Now().UTC())
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	return &kmsv1.DisableKeyResponse{}, nil
}

func (server *KMSServer) DestroyKey(ctx context.Context, req *kmsv1.DestroyKeyRequest) (*kmsv1.DestroyKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	err := server.repo.DestroyKey(ctx, req.UserId, req.KeyId)
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	return &kmsv1.DestroyKeyResponse{}, nil
}

func (server *KMSServer) RestoreKey(ctx context.Context, req *kmsv1.RestoreKeyRequest) (*kmsv1.RestoreKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user id is empty")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	err := server.repo.RestoreKey(ctx, req.UserId, req.KeyId)
	if err != nil {
		return nil, errorToGRPCError(err)
	}

	return &kmsv1.RestoreKeyResponse{}, nil
}

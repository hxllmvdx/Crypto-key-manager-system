package handlerG

import (
	"context"
	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	if req.Type == commonv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "key type has to be specified")
	}

	key, err := server.repo.GenerateKey(ctx, req.Type)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	metadata := key.KeyMetadata()

	return &kmsv1.GenerateKeyResponse{Metadata: metadata}, nil
}

func (server *KMSServer) GetKey(ctx context.Context, req *kmsv1.GetKeyRequest) (*kmsv1.GetKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	key, err := server.repo.GetKey(ctx, req.KeyId)
	if err != nil {
		return nil, err
	}

	metadata := key.KeyMetadata()

	protoKey := &kmsv1.Key{
		Metadata:    metadata,
		KeyMaterial: key.EncryptedKey,
	}

	return &kmsv1.GetKeyResponse{Key: protoKey}, nil
}

func (server *KMSServer) ListKeys(req *kmsv1.ListKeysRequest, stream grpc.ServerStreamingServer[kmsv1.ListKeysResponse]) error {
	keys, err := server.repo.ListKeys(stream.Context())
	if err != nil {
		return err
	}

	for _, key := range keys {
		response := &kmsv1.ListKeysResponse{
			Keys: key.KeyMetadata(),
		}

		if err := stream.Send(response); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}

func (server *KMSServer) RotateKey(ctx context.Context, req *kmsv1.RotateKeyRequest) (*kmsv1.RotateKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id has to be specified")
	}

	oldKey, err := server.repo.GetKey(ctx, req.KeyId)
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Error(codes.NotFound, err.Error())
	}

	keyType := oldKey.KeyType()
	if keyType == commonv1.KeyType_KEY_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "key type is not valid")
	}

	newKey, err := server.repo.RotateKey(ctx, req.KeyId, keyType)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	metadata := newKey.KeyMetadata()

	return &kmsv1.RotateKeyResponse{Metadata: metadata}, nil
}

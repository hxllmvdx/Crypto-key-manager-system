package handlerG

import (
	"errors"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/kmserrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errorToGRPCError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, kmserrors.ErrNotFound):
		return status.Error(codes.NotFound, "key not found")
	case errors.Is(err, kmserrors.ErrNotRotatable):
		return status.Error(codes.FailedPrecondition, "key not rotatable")
	case errors.Is(err, kmserrors.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

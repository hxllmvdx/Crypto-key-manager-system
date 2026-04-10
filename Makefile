.PHONY: generate-go
generate-go:
	protoc -I proto \
		--go_out=. --go_opt=module=github.com/hxllmvdx/Crypto-key-management-system \
		--go-grpc_out=. --go-grpc_opt=module=github.com/hxllmvdx/Crypto-key-management-system \
		proto/api/kms/v1/kms.proto \
		proto/api/common/v1/types.proto \
		proto/api/crypto/v1/crypto.proto

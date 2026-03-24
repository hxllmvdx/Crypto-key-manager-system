package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	cfg := config.Load()
	addr := fmt.Sprintf("localhost:%s", cfg.GRPCPort)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := kmsv1.NewKMSServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	genResp, err := client.GenerateKey(ctx, &kmsv1.GenerateKeyRequest{
		Type: commonv1.KeyType_KEY_TYPE_AES_256,
	})
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}

	keyID := genResp.GetMetadata().GetKeyId()
	fmt.Printf("generated key_id=%s version=%d status=%s type=%s\n",
		keyID,
		genResp.GetMetadata().GetVersion(),
		genResp.GetMetadata().GetStatus().String(),
		genResp.GetMetadata().GetType().String(),
	)

	getResp, err := client.GetKey(ctx, &kmsv1.GetKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("GetKey: %v", err)
	}

	fmt.Printf("got key version=%d status=%s\n",
		getResp.GetKey().GetMetadata().GetVersion(),
		getResp.GetKey().GetMetadata().GetStatus().String(),
	)

	stream, err := client.ListKeys(ctx, &kmsv1.ListKeysRequest{Empty: &emptypb.Empty{}})
	if err != nil {
		log.Fatalf("ListKeys: %v", err)
	}

	for {
		item, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("ListKeys Recv: %v", err)
		}

		m := item.GetKeys()
		fmt.Printf("list key_id=%s version=%d status=%s type=%s  created_at=%s updated_at=%s\n",
			m.GetKeyId(),
			m.GetVersion(),
			m.GetStatus().String(),
			m.GetType().String(),
			m.GetCreatedAt().AsTime().String(),
			m.GetUpdatedAt().AsTime().String(),
		)
	}

	rotResp, err := client.RotateKey(ctx, &kmsv1.RotateKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("RotateKey: %v", err)
	}

	fmt.Printf("rotated key version=%d status=%s\n",
		rotResp.GetMetadata().GetVersion(),
		rotResp.GetMetadata().GetStatus().String(),
	)

	getResp2, err := client.GetKey(ctx, &kmsv1.GetKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("GetKey after rotate: %v", err)
	}

	fmt.Printf("after rotate got version=%d status=%s key_material_len=%d created_at=%s updated_at=%s\n",
		getResp2.GetKey().GetMetadata().GetVersion(),
		getResp2.GetKey().GetMetadata().GetStatus().String(),
		len(getResp2.GetKey().GetKeyMaterial()),
		getResp2.GetKey().GetMetadata().GetCreatedAt().AsTime().String(),
		getResp2.GetKey().GetMetadata().GetUpdatedAt().AsTime().String(),
	)
}

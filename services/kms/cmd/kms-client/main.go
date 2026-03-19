// cmd/client/main.go
package main

import (
	"context"
	"flag"
	"log"
	"time"

	commonv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/common/v1"
	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr    = flag.String("addr", "localhost:50051", "gRPC server address")
	command = flag.String("cmd", "generate", "command: generate|get|list|rotate")
	keyID   = flag.String("key-id", "", "key ID for get/rotate")
	keyType = flag.String("type", "AES_256", "key type: AES_128|AES_256|RSA_2048")
)

func main() {
	flag.Parse()

	// Подключаемся к серверу
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("❌ Failed to connect: %v", err)
	}
	defer conn.Close()

	client := kmsv1.NewKMSServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch *command {
	case "generate":
		testGenerateKey(ctx, client)
	case "get":
		testGetKey(ctx, client)
	case "list":
		testListKeys(ctx, client)
	case "rotate":
		testRotateKey(ctx, client)
	default:
		log.Fatalf("❌ Unknown command: %s", *command)
	}
}

func testGenerateKey(ctx context.Context, client kmsv1.KMSServiceClient) {
	keyType := parseKeyType(*keyType)

	resp, err := client.GenerateKey(ctx, &kmsv1.GenerateKeyRequest{Type: keyType})
	if err != nil {
		log.Fatalf("❌ GenerateKey error: %v", err)
	}

	log.Printf("✅ Key generated: ID=%s, Version=%d", resp.Metadata.KeyId, resp.Metadata.Version)
}

func testGetKey(ctx context.Context, client kmsv1.KMSServiceClient) {
	if *keyID == "" {
		log.Fatal("❌ -key-id is required")
	}
	resp, err := client.GetKey(ctx, &kmsv1.GetKeyRequest{KeyId: *keyID})
	if err != nil {
		log.Fatalf("❌ GetKey error: %v", err)
	}
	log.Printf("✅ Key retrieved: ID=%s, Material=%d bytes", resp.Key.Metadata.KeyId, len(resp.Key.KeyMaterial))
}

func testListKeys(ctx context.Context, client kmsv1.KMSServiceClient) {
	stream, err := client.ListKeys(ctx, &kmsv1.ListKeysRequest{})
	if err != nil {
		log.Fatalf("❌ ListKeys error: %v", err)
	}
	log.Println("✅ Keys:")
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		log.Printf("   - %s (v%d)", resp.Keys.KeyId, resp.Keys.Version)
	}
}

func testRotateKey(ctx context.Context, client kmsv1.KMSServiceClient) {
	if *keyID == "" {
		log.Fatal("❌ -key-id is required")
	}
	resp, err := client.RotateKey(ctx, &kmsv1.RotateKeyRequest{KeyId: *keyID})
	if err != nil {
		log.Fatalf("❌ RotateKey error: %v", err)
	}
	log.Printf("✅ Key rotated: ID=%s, NewVersion=%d", resp.Metadata.KeyId, resp.Metadata.Version)
}

func parseKeyType(s string) commonv1.KeyType {
	switch s {
	case "AES_128":
		return commonv1.KeyType_KEY_TYPE_AES_128
	case "AES_256":
		return commonv1.KeyType_KEY_TYPE_AES_256
	case "RSA_2048":
		return commonv1.KeyType_KEY_TYPE_RSA_2048
	default:
		return commonv1.KeyType_KEY_TYPE_UNSPECIFIED
	}
}

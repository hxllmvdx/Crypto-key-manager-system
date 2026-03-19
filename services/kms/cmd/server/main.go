// main.go
package main

import (
	"log"
	"net"

	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/handler"

	"google.golang.org/grpc"
)

func main() {
	// Создаём listener на порту 50051
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("❌ Failed to listen: %v", err)
	}

	// Создаём gRPC-сервер
	grpcServer := grpc.NewServer()

	// Регистрируем наш KMS-сервер
	// ⚠️ Важно: методы в server.go должны иметь реализацию и return!
	kmsv1.RegisterKMSServiceServer(grpcServer, handlerG.NewKMSServer(nil))

	log.Println("✅ KMS Server started on :50051")

	// Запускаем сервер (блокирующий вызов)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("❌ Failed to serve: %v", err)
	}
}

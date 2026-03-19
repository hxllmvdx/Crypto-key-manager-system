package main

import (
	"log"
	"net"

	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/config"
	handler "github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/handler"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/repository"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/service"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	db, err := repository.NewDB(cfg)
	if err != nil {
		log.Fatalf("db init: %v", err)
	}

	keyRepo := repository.NewKeyRepository(db)
	keyService := service.NewKeyService(keyRepo)

	grpcServer := grpc.NewServer()
	kmsv1.RegisterKMSServiceServer(grpcServer, handler.NewKMSServer(keyService))

	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

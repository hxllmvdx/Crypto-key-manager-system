package handler

import "github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/service"

type GatewayHandler struct {
	svc *service.GatewayService
}

func NewGatewayHandler(svc *service.GatewayService) *GatewayHandler {
	return &GatewayHandler{svc: svc}
}

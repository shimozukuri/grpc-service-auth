package app

import (
	grpcapp "grpc-service/internal/app/grpc"
	"log/slog"
	"time"
)

type App struct {
	GRPCServ *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCServ: grpcApp,
	}
}

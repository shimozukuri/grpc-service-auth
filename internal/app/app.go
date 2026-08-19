package app

import (
	grpcapp "grpc-service/internal/app/grpc"
	"grpc-service/internal/services/auth"
	"grpc-service/internal/storage/sqlite"
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
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServ: grpcApp,
	}
}

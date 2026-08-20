package suite

import (
	"context"
	"grpc-service/internal/config"
	"net"
	"os"
	"strconv"
	"testing"

	grpcservicev1 "github.com/shimozukuri/grpc-service-protos/gen/go/grpc-service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient grpcservicev1.AuthClient
}

const (
	grpcHost = "localhost"
)

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()

	key := "CONFIG_PATH"

	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s must be set", key)
	}

	cfg := config.MustLoadByPath(v)

	ctx, cancelCtx := context.WithTimeout(
		context.Background(),
		cfg.GRPC.Timeout,
	)

	t.Cleanup(func() {
		cancelCtx()
	})

	cc, err := grpc.NewClient(
		grpcAddress(cfg),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc client connection failed: %v", err)
	}

	t.Cleanup(func() {
		_ = cc.Close()
	})

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: grpcservicev1.NewAuthClient(cc),
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
}

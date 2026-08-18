package auth

import (
	"context"

	grpcservicev1 "github.com/shimozukuri/grpc-service-protos/gen/go/grpc-service"
	"google.golang.org/grpc"
)

type serverAPI struct {
	grpcservicev1.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) {
	grpcservicev1.RegisterAuthServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Login(
	ctx context.Context,
	in *grpcservicev1.LoginRequest,
) (*grpcservicev1.LoginResponse, error) {
	return &grpcservicev1.LoginResponse{
		Token: in.GetEmail(),
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	in *grpcservicev1.RegisterRequest,
) (*grpcservicev1.RegisterResponse, error) {
	panic("implement me")
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	in *grpcservicev1.IsAdminRequest,
) (*grpcservicev1.IsAdminResponse, error) {
	panic("implement me")
}

package main

import (
	"fmt"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/grpclog"

	pb "github.com/TykTechnologies/tyk/coprocess"
)

type TykGrpcServer struct {
}

func(s *TykGrpcServer) Dispatch	(ctx context.Context, object *pb.Object) (*pb.Object, error) {
	fmt.Println("Receiving object:", object)
	return object, nil
}

func main() {
	lis, err := net.Listen("tcp", "127.0.0.1:5555")
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	s := new(TykGrpcServer)
	pb.RegisterDispatcherServer(grpcServer, s)
	grpcServer.Serve(lis)
}

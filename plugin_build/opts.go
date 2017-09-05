package main

import "google.golang.org/grpc"

func getOpts() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithInsecure(),
	}
}

var doRegister = changeMe

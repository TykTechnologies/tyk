package main

import (
	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"plugin"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"strings"
)

var gRPCProxyMux *runtime.ServeMux = runtime.NewServeMux()

func loadGRPCProxyPlugin(path string, spec *APISpec) error {
	var err error
	var p *plugin.Plugin
	var serviceAdd plugin.Symbol

	// Load our plugin
	if p, err = plugin.Open(path); err != nil {
		log.Fatal(err)
		return err
	}

	// We need to know the service name in order to find the registration func
	registrationName := fmt.Sprintf("Register%sHandlerFromEndpoint", spec.CustomMiddleware.GRPCProxy.Name)
	if serviceAdd, err = p.Lookup(registrationName); err != nil {
		log.Fatal(err)
		return err
	}

	// TODO: Needs to be configurable
	opts := []grpc.DialOption{grpc.WithInsecure()}

	endpoint := strings.Replace(spec.Proxy.TargetURL, "http://", "", 1)
	endpoint = strings.Replace(endpoint, "https://", "", 1)

	// Call the registration function and add to grpc muxer, needs a type cast
	ctx := context.Background()
	ctx, _ = context.WithCancel(ctx)
	if err = serviceAdd.(func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error)(ctx, gRPCProxyMux, endpoint, opts); err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}
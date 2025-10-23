package gateway

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

var (
	grpcConnection *grpc.ClientConn
	grpcClient     coprocess.DispatcherClient
)

// GRPCDispatcher implements a coprocess.Dispatcher
type GRPCDispatcher struct {
	coprocess.Dispatcher
}

func (gw *Gateway) GetCoProcessGrpcServerTargetURL() (*url.URL, error) {
	grpcURL, err := url.Parse(gw.GetConfig().CoProcessOptions.CoProcessGRPCServer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}

	if grpcURL == nil || gw.GetConfig().CoProcessOptions.CoProcessGRPCServer == "" {
		errString := "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(errString)
		return nil, err
	}
	return grpcURL, nil
}

func GetCoProcessGrpcServerTargetUrlAsString(targetUrl *url.URL) string {
	return strings.TrimPrefix(targetUrl.String(), "tcp://")
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
// This is the backward-compatible method that uses context.Background().
func (d *GRPCDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	return d.DispatchWithContext(context.Background(), object)
}

// DispatchWithContext takes a context and a CoProcessMessage and sends it to the CP.
// The context is used to propagate trace context to the gRPC plugin.
func (d *GRPCDispatcher) DispatchWithContext(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	// Use the provided context instead of context.Background() to propagate trace context
	if ctx == nil {
		ctx = context.Background()
	}
	return grpcClient.Dispatch(ctx, object)
}

// DispatchObject is deprecated. Use Dispatch or DispatchWithContext instead.
func (d *GRPCDispatcher) DispatchObject(object *coprocess.Object) (*coprocess.Object, error) {
	return d.Dispatch(object)
}

// DispatchEvent dispatches a Tyk event.
func (d *GRPCDispatcher) DispatchEvent(eventJSON []byte) {
	eventObject := &coprocess.Event{
		Payload: string(eventJSON),
	}

	_, err := grpcClient.DispatchEvent(context.Background(), eventObject)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *GRPCDispatcher) Reload() {}

// HandleMiddlewareCache isn't used by gRPC.
func (d *GRPCDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {}

func (gw *Gateway) grpcCallOpts() grpc.DialOption {
	recvSize := gw.GetConfig().CoProcessOptions.GRPCRecvMaxSize
	sendSize := gw.GetConfig().CoProcessOptions.GRPCSendMaxSize
	var opts []grpc.CallOption
	if recvSize > 0 {
		opts = append(opts, grpc.MaxCallRecvMsgSize(recvSize))
	}
	if sendSize > 0 {
		opts = append(opts, grpc.MaxCallSendMsgSize(sendSize))
	}
	return grpc.WithDefaultCallOptions(opts...)
}

// NewGRPCDispatcher wraps all the actions needed for this CP.
func (gw *Gateway) NewGRPCDispatcher() (coprocess.Dispatcher, error) {
	if gw.GetConfig().CoProcessOptions.CoProcessGRPCServer == "" {
		return nil, errors.New("No gRPC URL is set")
	}

	var err error
	grpcUrl, err := gw.GetCoProcessGrpcServerTargetURL()
	if err != nil {
		return nil, err
	}

	dialOptions := []grpc.DialOption{
		gw.grpcCallOpts(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Add OpenTelemetry gRPC interceptors for automatic trace context propagation
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	}
	
	authority := gw.GetConfig().CoProcessOptions.GRPCAuthority
	if authority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(authority))
	}

	isRoundRobinEnabled := gw.GetConfig().CoProcessOptions.GRPCRoundRobinLoadBalancing
	if isRoundRobinEnabled {
		dialOptions = append(dialOptions, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))
	}

	grpcConnection, err = grpc.NewClient(
		GetCoProcessGrpcServerTargetUrlAsString(grpcUrl),
		dialOptions...,
	)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)
	return &GRPCDispatcher{}, nil
}

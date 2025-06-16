package gateway

import (
	"context"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

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

func (gw *Gateway) dialer(_ string, timeout time.Duration) (net.Conn, error) {
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
		return nil, errors.New(errString)
	}

	grpcURLString := gw.GetConfig().CoProcessOptions.CoProcessGRPCServer[len(grpcURL.Scheme)+3:]
	return net.DialTimeout(grpcURL.Scheme, grpcURLString, timeout)
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *GRPCDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	return grpcClient.Dispatch(context.Background(), object)
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
	authority := gw.GetConfig().CoProcessOptions.GRPCAuthority

	var err error
	grpcConnection, err = grpc.Dial("",
		gw.grpcCallOpts(),
		grpc.WithInsecure(),
		grpc.WithAuthority(authority),
		grpc.WithDialer(gw.dialer),
	)

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

<<<<<<< HEAD
=======
	isRoundRobinEnabled := gw.GetConfig().CoProcessOptions.GRPCRoundRobinLoadBalancing
	if isRoundRobinEnabled {
		dialOptions = append(dialOptions, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))
	}

	grpcConnection, err = grpc.NewClient(
		GetCoProcessGrpcServerTargetUrlAsString(grpcUrl),
		dialOptions...,
	)
>>>>>>> b44f7909f... [TT-10496] gRPC plugins do not terminate gracefully and cannot be load balanced (#7111)
	if err != nil {

		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}
	return &GRPCDispatcher{}, nil
}

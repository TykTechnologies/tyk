package gateway

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net/url"

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

func GetCoProcessGrpcServerTargetUrlAsString(url *url.URL) string {
	return url.String()[len(url.Scheme)+3:]
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
	//grpcConnection, err = grpc.Dial("",
	//	gw.grpcCallOpts(),
	//	grpc.WithInsecure(),
	//	grpc.WithAuthority(authority),
	//	grpc.WithDialer(gw.dialer),
	//)
	grpcUrl, err := gw.GetCoProcessGrpcServerTargetURL()
	if err != nil {
		return nil, err
	}
	grpcConnection, err = grpc.NewClient(
		GetCoProcessGrpcServerTargetUrlAsString(grpcUrl),
		gw.grpcCallOpts(),
		grpc.WithAuthority(authority),
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	if err != nil {

		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}
	return &GRPCDispatcher{}, nil
}

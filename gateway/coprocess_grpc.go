package gateway

import (
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
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

func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	grpcURL, err := url.Parse(config.Global().CoProcessOptions.CoProcessGRPCServer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}

	if grpcURL == nil || config.Global().CoProcessOptions.CoProcessGRPCServer == "" {
		errString := "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(errString)
		return nil, errors.New(errString)
	}

	grpcURLString := config.Global().CoProcessOptions.CoProcessGRPCServer[len(grpcURL.Scheme)+3:]
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

// NewGRPCDispatcher wraps all the actions needed for this CP.
func NewGRPCDispatcher() (coprocess.Dispatcher, error) {
	if config.Global().CoProcessOptions.CoProcessGRPCServer == "" {
		return nil, errors.New("No gRPC URL is set")
	}
	var err error
	grpcConnection, err = grpc.Dial("", grpc.WithInsecure(), grpc.WithDialer(dialer))
	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}
	return &GRPCDispatcher{}, nil
}

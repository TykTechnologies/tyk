// +build coprocess
// +build grpc

package main

import (
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
)

// CoProcessName specifies the driver name.
const CoProcessName = apidef.GrpcDriver

// MessageType sets the default message type.
var MessageType = coprocess.ProtobufMessage

var grpcConnection *grpc.ClientConn
var grpcClient coprocess.DispatcherClient

// GRPCDispatcher implements a coprocess.Dispatcher
type GRPCDispatcher struct {
	coprocess.Dispatcher
}

func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	grpcUrl, err := url.Parse(config.Global().CoProcessOptions.CoProcessGRPCServer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return nil, err
	}

	if grpcUrl == nil || config.Global().CoProcessOptions.CoProcessGRPCServer == "" {
		errString := "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(errString)
		return nil, errors.New(errString)
	}

	grpcUrlString := config.Global().CoProcessOptions.CoProcessGRPCServer[len(grpcUrl.Scheme)+3:]
	return net.DialTimeout(grpcUrl.Scheme, grpcUrlString, timeout)
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *GRPCDispatcher) DispatchObject(object *coprocess.Object) (*coprocess.Object, error) {
	newObject, err := grpcClient.Dispatch(context.Background(), object)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}
	return newObject, err
}

// DispatchEvent dispatches a Tyk event.
func (d *GRPCDispatcher) DispatchEvent(eventJSON []byte) {
	eventObject := &coprocess.Event{
		Payload: string(eventJSON),
	}

	_, err := grpcClient.DispatchEvent(context.Background(), eventObject)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *GRPCDispatcher) Reload() {}

// HandleMiddlewareCache isn't used by gRPC.
func (d *GRPCDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (coprocess.Dispatcher, error) {
	var err error
	grpcConnection, err = grpc.Dial("", grpc.WithInsecure(), grpc.WithDialer(dialer))
	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return nil, err
	}
	return &GRPCDispatcher{}, nil
}

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	return GlobalDispatcher.DispatchObject(object)
}

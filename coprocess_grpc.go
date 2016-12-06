// +build coprocess
// +build grpc

package main

import (
	"net"
	"net/url"
	"time"
	"errors"

	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tykcommon"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// CoProcessName specifies the driver name.
const CoProcessName string = "grpc"

// MessageType sets the default message type.
var MessageType = coprocess.ProtobufMessage

var grpcConnection *grpc.ClientConn
var grpcClient coprocess.DispatcherClient

// GRPCDispatcher implements a coprocess.Dispatcher
type GRPCDispatcher struct {
	coprocess.Dispatcher
}

func dialer(addr string, timeout time.Duration) (conn net.Conn, err error) {
	var grpcUrl *url.URL
	grpcUrl, err = url.Parse(config.CoProcessOptions.CoProcessGRPCServer)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return nil, err
	}

	if grpcUrl == nil || config.CoProcessOptions.CoProcessGRPCServer == "" {
		var errString = "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(errString)
		return nil, errors.New(errString)
	}

	grpcUrlString := config.CoProcessOptions.CoProcessGRPCServer[len(grpcUrl.Scheme)+3 : len(config.CoProcessOptions.CoProcessGRPCServer)]

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
	eventObject := &coprocess.Event{string(eventJSON)}

	_, err := grpcClient.DispatchEvent(context.Background(), eventObject)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}

	return
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *GRPCDispatcher) Reload() {
	return
}

// HandleMiddlewareCache isn't used by gRPC.
func (d* GRPCDispatcher) HandleMiddlewareCache(b *tykcommon.BundleManifest, basePath string) {
	return
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher coprocess.Dispatcher, err error) {

	dispatcher, err = &GRPCDispatcher{}, nil

	grpcConnection, err = grpc.Dial("", grpc.WithInsecure(), grpc.WithDialer(dialer))

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}

	return dispatcher, err
}

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) (newObject *coprocess.Object, err error) {
	newObject, err = GlobalDispatcher.DispatchObject(object)
	return newObject, err
}

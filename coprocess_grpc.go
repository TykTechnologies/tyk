// +build coprocess
// +build grpc

package main

import (
	"net"
	"net/url"
	"time"
	// "strings"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/coprocess"
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

	grpcUrlString := config.CoProcessOptions.CoProcessGRPCServer[len(grpcUrl.Scheme)+3 : len(config.CoProcessOptions.CoProcessGRPCServer)]

	return net.DialTimeout(grpcUrl.Scheme, grpcUrlString, timeout)
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *GRPCDispatcher) DispatchObject(object *coprocess.Object) *coprocess.Object {
	newObject, err := grpcClient.Dispatch(context.Background(), object)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return object
	}
	return newObject
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
func (c *CoProcessor) Dispatch(object *coprocess.Object) *coprocess.Object {
	object = GlobalDispatcher.DispatchObject(object)
	return object
}

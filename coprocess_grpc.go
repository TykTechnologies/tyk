// +build coprocess
// +build grpc

package main

import (
	"C"
	"net"
	"time"
	// "strings"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/coprocess"
)

// CoProcessName specifies the driver name.
const CoProcessName string = "grpc"

const(
	address = "127.0.0.1:5555"
)

// MessageType sets the default message type.
var MessageType = coprocess.ProtobufMessage

var grpcConnection *grpc.ClientConn
var grpcClient coprocess.DispatcherClient

// GRPCDispatcher implements a coprocess.Dispatcher
type GRPCDispatcher struct {
	// GRPCDispatcher implements the coprocess.Dispatcher interface.
	coprocess.Dispatcher
}

func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	// return net.DialTimeout("unix", addr, timeout)
	return net.DialTimeout("tcp", addr, timeout)
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

	grpcConnection, err = grpc.Dial(address, grpc.WithInsecure())

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}

	return dispatcher, err
}

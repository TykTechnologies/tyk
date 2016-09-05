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
		panic(err)
	}
	return newObject
}

// Reload will perform a middleware reload when a hot reload is triggered.
func (d *GRPCDispatcher) Reload() {
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher coprocess.Dispatcher, err error) {

	dispatcher, err = &GRPCDispatcher{}, nil

	grpcConnection, err = grpc.Dial(address, grpc.WithInsecure())
	// defer grpcConnection.Close()

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)

	// dispatcher.LoadModules()

	// dispatcher.Reload()

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}

	return dispatcher, err
}

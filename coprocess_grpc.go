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
	"github.com/TykTechnologies/tyk/coprocess"
)

const CoProcessName = "test"

// MessageType sets the default message type.
var MessageType = coprocess.ProtobufMessage

var grpcConnection *grpc.ClientConn
var grpcClient coprocess.DispatcherClient

// GRPCDriver wraps the driver methods.
type GRPCDriver coprocess.Driver

func (d *GRPCDriver) dialer(addr string, timeout time.Duration) (net.Conn, error) {
	grpcURL, err := url.Parse(globalConf.CoProcessOptions.CoProcessGRPCServer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return nil, err
	}

	if grpcURL == nil || globalConf.CoProcessOptions.CoProcessGRPCServer == "" {
		errString := "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(errString)
		return nil, errors.New(errString)
	}

	grpcURLString := globalConf.CoProcessOptions.CoProcessGRPCServer[len(grpcURL.Scheme)+3:]
	return net.DialTimeout(grpcURL.Scheme, grpcURLString, timeout)
}

// DispatchObject takes a CoProcessMessage and sends it to the CP.
func (d *GRPCDriver) DispatchObject(object *coprocess.Object) (*coprocess.Object, error) {
	newObject, err := grpcClient.Dispatch(context.Background(), object)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
	}
	return newObject, err
}

// DispatchEvent dispatches a Tyk event.
func (d *GRPCDriver) DispatchEvent(eventJSON []byte) {
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

// HandleMiddlewareCache isn't used by gRPC.
func (d *GRPCDriver) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {}

// Init wraps all the initial actions needed for this CP.
func (d *GRPCDriver) Init() error {
	var err error
	grpcConnection, err = grpc.Dial("", grpc.WithInsecure(), grpc.WithDialer(d.dialer))
	grpcClient = coprocess.NewDispatcherClient(grpcConnection)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess-grpc",
		}).Error(err)
		return err
	}
	return nil
}

// Reload isn't used by gRPC.
func (d *GRPCDriver) Reload() {}

// LoadModules isn't used by gRPC.
func (d *GRPCDriver) LoadModules() {}

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	return GlobalDispatcher.DispatchObject(object)
}

func init() {
	driver := GRPCDriver{}
	Drivers[apidef.GrpcDriver] = &driver
}

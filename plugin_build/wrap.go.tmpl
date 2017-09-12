package main

import (
	"golang.org/x/net/context"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"errors"
	"google.golang.org/grpc"
)


type registerFunc func (context.Context, *runtime.ServeMux, string, []grpc.DialOption) (err error)

// errInvalidConfig is the error returned when a module is initialized
// with an invalid configuration argument
var errInvalidConfig = errors.New("invalid config")

// Config is a configuration provider
type Config interface {
	// Get returns the value for the specified key
	Get(ctx context.Context, key string) interface{}
}

// Types is the symbol the host process uses to
// retrieve the plug-in's type map
var Types = map[string]func() interface{}{
	"register": func() interface{} { return &module{} },
}

type module struct{
}

func (m *module) Init(ctx context.Context, configObj interface{}) error {
	config, configOk := configObj.(Config)
	if !configOk {
		return errors.New("Invalid config")
	}

	doRegister(
		config.Get(ctx,"ctx").(context.Context),
		config.Get(ctx,"mux").(*runtime.ServeMux),
		config.Get(ctx,"e").(string),
		getOpts())

	return nil
}

// Do not edit this function
func changeMe(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	return nil
}
package grpcproxy

import (
	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"fmt"
	"plugin"
	"strings"

	"github.com/akutz/gpds/lib"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func LoadGRPCProxyPlugin(path string, targetURL string, gRPCProxyMux *runtime.ServeMux) error {
	// Load our plugin
	p, err := plugin.Open(path)
	if err != nil {
		return err
	}

	// lookup the plug-in's Types symbol; it's the type map used to
	// register the plug-in's modules
	tmapObj, err := p.Lookup("Types")
	if err != nil {
		return fmt.Errorf("failed to lookup type map: %v", err)
	}

	// assert that the Types symbol is a *map[string]func() interface{}
	tmapPtr, tmapOk := tmapObj.(*map[string]func() interface{})
	if !tmapOk {
		return fmt.Errorf("invalid type map: %T", tmapObj)
	}

	// assert that the type map pointer is not nil
	if tmapPtr == nil {
		return fmt.Errorf("Map pointer is nil: %v", tmapPtr)
	}

	// dereference the type map pointer
	tmap := *tmapPtr

	// register the plug-in's modules
	for k, v := range tmap {
		lib.RegisterModule(k, v)
	}

	// Instantiate a copy of the module registered by the plug-in.
	modGo := lib.NewModule("register")

	endpoint := strings.Replace(targetURL, "http://", "", 1)
	endpoint = strings.Replace(endpoint, "https://", "", 1)

	// Create a new v2 config
	config := &v2Config{
		ctx:        context.Background(), // used by the grpC Proxy registration func
		mux:        gRPCProxyMux,
		entrypoint: endpoint,
	}

	// Initialize mod_go with a v2 config implementation
	if err := modGo.Init(context.Background(), config); err != nil {
		return err
	}

	return nil
}

type v2Config struct {
	ctx        context.Context
	mux        *runtime.ServeMux
	entrypoint string
	opts       []grpc.DialOption
}

// Get returns the value for the specified key
func (c *v2Config) Get(ctx context.Context, key string) interface{} {
	switch key {
	case "ctx":
		return c.ctx
	case "mux":
		return c.mux
	case "e":
		return c.entrypoint
	case "opts":
		return c.opts
	}

	return nil
}

// Set sets the value for the specified key
func (c *v2Config) Set(ctx context.Context, key string, val interface{}) {
	switch key {
	case "ctx":
		c.ctx = val.(context.Context)
	case "mux":
		c.mux = val.(*runtime.ServeMux)
	case "e":
		c.entrypoint = val.(string)
	case "opts":
		c.opts = val.([]grpc.DialOption)
	}
}

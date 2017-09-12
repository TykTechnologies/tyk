package grpcproxy

import (
	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"fmt"
	"log"
	"os"
	"plugin"
	"strings"

	"github.com/akutz/gpds/lib"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type conf struct{}

func LoadGRPCProxyPlugin(path string, targetURL string, gRPCProxyMux *runtime.ServeMux) error {
	var err error
	var p *plugin.Plugin

	// Load our plugin
	if p, err = plugin.Open(path); err != nil {
		log.Fatal(err)
		return err
	}

	// lookup the plug-in's Types symbol; it's the type map used to
	// register the plug-in's modules
	tmapObj, err := p.Lookup("Types")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to lookup type map: %v\n", err)
		os.Exit(1)
	}

	// assert that the Types symbol is a *map[string]func() interface{}
	tmapPtr, tmapOk := tmapObj.(*map[string]func() interface{})
	if !tmapOk {
		fmt.Fprintf(os.Stderr, "error: invalid type map: %T\n", tmapObj)
		os.Exit(1)
	}

	// assert that the type map pointer is not nil
	if tmapPtr == nil {
		fmt.Fprintf(
			os.Stderr, "error: nil type map: type=%[1]T val=%[1]v\n", tmapPtr)
		os.Exit(1)
	}

	// dereference the type map pointer
	tmap := *tmapPtr

	// register the plug-in's modules
	for k, v := range tmap {
		lib.RegisterModule(k, v)
	}

	// Instantiate a copy of the module registered by the plug-in.
	modGo := lib.NewModule("register")

	ctx := context.Background()
	ctx, _ = context.WithCancel(ctx)

	endpoint := strings.Replace(targetURL, "http://", "", 1)
	endpoint = strings.Replace(endpoint, "https://", "", 1)

	// Create a new v2 config
	config := &v2Config{
		ctx: ctx,
		mux: gRPCProxyMux,
		e:   endpoint,
	}

	// Initialize mod_go with a v2 config implementation
	if err := modGo.Init(ctx, config); err != nil {
		return err
	}

	return nil
}

type v2Config struct {
	ctx  context.Context
	mux  *runtime.ServeMux
	e    string
	opts []grpc.DialOption
}

// Get returns the value for the specified key
func (c *v2Config) Get(ctx context.Context, key string) interface{} {
	switch key {
	case "ctx":
		return c.ctx
	case "mux":
		return c.mux
	case "e":
		return c.e
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
		c.e = val.(string)
	case "opts":
		c.opts = val.([]grpc.DialOption)
	}
}

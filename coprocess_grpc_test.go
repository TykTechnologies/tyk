// +build coprocess
// +build grpc

package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"context"

	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/test"
)

const (
	grpcListenAddr = ":9999"
	grpcListenPath = "tcp://127.0.0.1:9999"

	testHeaderName  = "Testheader"
	testHeaderValue = "testvalue"
)

type dispatcher struct{}

func (d *dispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	switch object.HookName {
	case "testPreHook1":
		object.Request.SetHeaders = map[string]string{
			testHeaderName: testHeaderValue,
		}
	}
	return object, nil
}

func (d *dispatcher) DispatchEvent(ctx context.Context, event *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}

func newTestGRPCServer() (s *grpc.Server) {
	s = grpc.NewServer()
	coprocess.RegisterDispatcherServer(s, &dispatcher{})
	return s
}

func loadTestGRPCSpec() *APISpec {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "999999"
		spec.OrgID = "default"
		spec.Auth = apidef.Auth{
			AuthHeaderName: "authorization",
		}
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					Name: "v1",
				},
			},
		}
		spec.Proxy.ListenPath = "/grpc-test-api/"
		spec.Proxy.StripListenPath = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{Name: "testPreHook1"},
			},
			Driver: apidef.GrpcDriver,
		}
	})[0]

	return spec
}

func startTykWithGRPC() (*tykTestServer, *grpc.Server) {
	// Setup the gRPC server:
	listener, _ := net.Listen("tcp", grpcListenAddr)
	grpcServer := newTestGRPCServer()
	go grpcServer.Serve(listener)

	// Setup Tyk:
	cfg := config.CoProcessConfig{
		EnableCoProcess:     true,
		CoProcessGRPCServer: grpcListenPath,
	}
	ts := newTykTestServer(tykTestServerConfig{coprocessConfig: cfg})

	// Load a test API:
	loadTestGRPCSpec()
	return &ts, grpcServer
}

func TestGRPCDispatch(t *testing.T) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	t.Run("Pre Hook with SetHeaders", func(t *testing.T) {
		res, err := ts.Run(t, test.TestCase{
			Path:   "/grpc-test-api/",
			Method: http.MethodGet,
			Code:   http.StatusOK,
		})
		if err != nil {
			t.Fatalf("Request failed: %s", err.Error())
		}
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Couldn't read response body: %s", err.Error())
		}
		var testResponse testHttpResponse
		err = json.Unmarshal(data, &testResponse)
		if err != nil {
			t.Fatalf("Couldn't unmarshal test response JSON: %s", err.Error())
		}
		value, ok := testResponse.Headers[testHeaderName]
		if !ok {
			t.Fatalf("Header not found, expecting %s", testHeaderName)
		}
		if value != testHeaderValue {
			t.Fatalf("Header value isn't %s", testHeaderValue)
		}
	})

}

func BenchmarkGRPCDispatch(b *testing.B) {
	ts, grpcServer := startTykWithGRPC()
	defer ts.Close()
	defer grpcServer.Stop()

	b.Run("Pre Hook with SetHeaders", func(b *testing.B) {
		path := "/grpc-test-api/"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ts.Run(b, test.TestCase{
				Path:   path,
				Method: http.MethodGet,
				Code:   http.StatusOK,
			})
		}
	})
}

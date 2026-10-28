package grpc

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

// startTT14580Services starts the coprocess gRPC harness for TT-14580: the
// Gateway's own GRPCRecvMaxSize/GRPCSendMaxSize are always raised; only the
// plugin server's own grpc.Server options vary between the two tests below.
func startTT14580Services(t *testing.T, serverOpts ...grpc.ServerOption) *gateway.Test {
	t.Helper()

	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer(serverOpts...)
	coprocess.RegisterDispatcherServer(grpcServer, &dispatcher{})
	go grpcServer.Serve(listener)
	t.Cleanup(grpcServer.Stop)

	conf := config.CoProcessConfig{
		EnableCoProcess:     true,
		CoProcessGRPCServer: grpcServerAddress(listener),
		GRPCRecvMaxSize:     grpcTestMaxSize,
		GRPCSendMaxSize:     grpcTestMaxSize,
		GRPCAuthority:       grpcAuthority,
	}
	ts := gateway.StartTest(nil, gateway.TestConfig{CoprocessConfig: conf})
	t.Cleanup(ts.Close)

	ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.APIID = "tt14580"
		spec.OrgID = gateway.MockOrgID
		spec.UseKeylessAccess = true
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {Name: "v1"},
			},
		}
		spec.Proxy.ListenPath = "/tt14580/"
		spec.Proxy.StripListenPath = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Pre:    []apidef.MiddlewareDefinition{{Name: "testPreHook1"}},
			Driver: apidef.GrpcDriver,
		}
	})

	return ts
}

func TestTT14580(t *testing.T) {

	t.Run("current behavior", func(t *testing.T) {
		t.Run("PluginServerDefaultLimitRejectsLargeBody", func(t *testing.T) {
			//  reproduces the customer
			// symptom: the Gateway's own gRPC limits are raised, but the plugin server
			// keeps grpc-go's default ~4MB receive limit, so a large request is rejected.
			ts := startTT14580Services(t) // no server-side options: grpc-go defaults apply

			body := randStringBytes(11 * 1024 * 1024)
			_, err := ts.Run(t, test.TestCase{
				Path:   "/tt14580/",
				Method: http.MethodPost,
				Code:   http.StatusInternalServerError, // However 502 (http.StatusBadGateway) or (413) is appropriate response
				Data:   body,
			})
			assert.NoError(t, err)
		})

		t.Run("RaisingPluginServerLimitFixesIt", func(t *testing.T) {
			// RaisingPluginServerLimitFixesIt isolates the variable: same
			// Gateway config as above, only the plugin server's own MaxRecvMsgSize changes.
			ts := startTT14580Services(t, grpc.MaxRecvMsgSize(grpcTestMaxSize))

			body := randStringBytes(11 * 1024 * 1024)
			_, err := ts.Run(t, test.TestCase{
				Path:   "/tt14580/",
				Method: http.MethodPost,
				Code:   http.StatusOK,
				Data:   body,
			})
			assert.NoError(t, err)
		})
	})
}

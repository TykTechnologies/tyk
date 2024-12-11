package grpc

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/gateway"
)

func newTestGRPCServer() (s *grpc.Server) {
	s = grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcTestMaxSize),
		grpc.MaxSendMsgSize(grpcTestMaxSize),
	)
	coprocess.RegisterDispatcherServer(s, &dispatcher{})
	return s
}

func startTestServices(t testing.TB) (*gateway.Test, func()) {
	// attempt auto closing grpc server listen addr
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	assert.NoError(t, err)

	grpcServer := newTestGRPCServer()
	go func() {
		err := grpcServer.Serve(listener)
		require.NoError(t, err)
	}()

	conf := config.CoProcessConfig{
		EnableCoProcess:     true,
		CoProcessGRPCServer: grpcServerAddress(listener),
		GRPCRecvMaxSize:     grpcTestMaxSize,
		GRPCSendMaxSize:     grpcTestMaxSize,
		GRPCAuthority:       grpcAuthority,
	}

	ts := gateway.StartTest(nil, gateway.TestConfig{
		CoprocessConfig: conf,
	})
	// Load test APIs:
	loadTestGRPCAPIs(ts)

	shutdown := stopTestServices(ts, grpcServer, listener)

	t.Logf("Started with conf.CoProcessGRPCServer %q", conf.CoProcessGRPCServer)

	return ts, shutdown
}

func grpcServerAddress(l net.Listener) string {
	addr := l.Addr()
	target := addr.String()
	// we need a routable address
	target = strings.ReplaceAll(target, "[::]", "localhost")

	return addr.Network() + "://" + target
}

func stopTestServices(ts *gateway.Test, grpcServer *grpc.Server, listener net.Listener) func() {
	return func() {
		ts.Close()
		grpcServer.Stop()
		listener.Close()
	}
}

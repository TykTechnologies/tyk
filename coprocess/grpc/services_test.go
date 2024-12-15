package grpc

import (
	"net"
	"testing"

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

func startTestServices(tb testing.TB) (*gateway.Test, func()) {
	tb.Helper()

	listener, err := net.Listen("tcp", ":0")
	require.NoError(tb, err)

	grpcServer := newTestGRPCServer()
	go func() {
		err := grpcServer.Serve(listener)
		require.NoError(tb, err)
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

	tb.Logf("Started with conf.CoProcessGRPCServer %q", conf.CoProcessGRPCServer)

	return ts, shutdown
}

func grpcServerAddress(l net.Listener) string {
	addr := l.Addr()
	target := addr.String()
	return addr.Network() + "://" + target
}

func stopTestServices(ts *gateway.Test, grpcServer *grpc.Server, listener net.Listener) func() {
	return func() {
		ts.Close()
		grpcServer.Stop()
		listener.Close()
	}
}

package gateway

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/internal/grpcresolver"
)

var (
	grpcConnection *grpc.ClientConn
	grpcClient     coprocess.DispatcherClient
)

// GRPCDispatcher implements a coprocess.Dispatcher
type GRPCDispatcher struct {
	coprocess.Dispatcher
}

func (gw *Gateway) GetCoProcessGrpcServerTargetURL() (*url.URL, error) {
	grpcURL, err := url.Parse(gw.GetConfig().CoProcessOptions.CoProcessGRPCServer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}

	if grpcURL == nil || gw.GetConfig().CoProcessOptions.CoProcessGRPCServer == "" {
		errString := "No gRPC URL is set!"
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(errString)
		return nil, err
	}
	return grpcURL, nil
}

func GetCoProcessGrpcServerTargetUrlAsString(targetUrl *url.URL) string {
	return strings.TrimPrefix(targetUrl.String(), "tcp://")
}

// bareGRPCEndpoint reduces a configured coprocess_grpc_server address to the
// host:port a resolver needs, and reports whether it could.
//
// The configured value carries a naming scheme that says which resolver
// grpc-go should use, and all the documented forms have to be understood here.
// `dns:///plugin:9001` in particular is what the round-robin option's own
// documentation tells operators to write, and it is not a URL whose host is the
// endpoint: the endpoint is in the path, after an optional DNS-server
// authority.
func bareGRPCEndpoint(raw string) (string, bool) {
	endpoint := strings.TrimSpace(raw)

	switch {
	case strings.HasPrefix(endpoint, "tcp://"):
		endpoint = strings.TrimPrefix(endpoint, "tcp://")
	case strings.HasPrefix(endpoint, "dns:"):
		// dns:host:port, dns:///host:port, or dns://authority/host:port.
		if i := strings.LastIndex(endpoint, "/"); i >= 0 {
			endpoint = endpoint[i+1:]
		} else {
			endpoint = strings.TrimPrefix(endpoint, "dns:")
		}
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || strings.ContainsAny(host, "/:") {
		return "", false
	}
	// SplitHostPort is happy with any trailing segment, so "unix:///a/b" splits
	// as host "unix" and port "///a/b". Require a real port number.
	if _, err := strconv.Atoi(port); err != nil {
		return "", false
	}
	return endpoint, true
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *GRPCDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	return d.DispatchWithContext(context.Background(), object)
}

// DispatchWithContext takes a context and CoProcessMessage and sends it to the CP with trace propagation.
func (d *GRPCDispatcher) DispatchWithContext(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	return grpcClient.Dispatch(ctx, object)
}

// DispatchEvent dispatches a Tyk event.
func (d *GRPCDispatcher) DispatchEvent(eventJSON []byte) {
	eventObject := &coprocess.Event{
		Payload: string(eventJSON),
	}

	_, err := grpcClient.DispatchEvent(context.Background(), eventObject)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *GRPCDispatcher) Reload() {}

// HandleMiddlewareCache isn't used by gRPC.
func (d *GRPCDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {}

func (gw *Gateway) grpcCallOpts() grpc.DialOption {
	recvSize := gw.GetConfig().CoProcessOptions.GRPCRecvMaxSize
	sendSize := gw.GetConfig().CoProcessOptions.GRPCSendMaxSize
	var opts []grpc.CallOption
	if recvSize > 0 {
		opts = append(opts, grpc.MaxCallRecvMsgSize(recvSize))
	}
	if sendSize > 0 {
		opts = append(opts, grpc.MaxCallSendMsgSize(sendSize))
	}
	return grpc.WithDefaultCallOptions(opts...)
}

// NewGRPCDispatcher wraps all the actions needed for this CP.
func (gw *Gateway) NewGRPCDispatcher() (coprocess.Dispatcher, error) {
	if gw.GetConfig().CoProcessOptions.CoProcessGRPCServer == "" {
		return nil, errors.New("No gRPC URL is set")
	}

	var err error
	grpcUrl, err := gw.GetCoProcessGrpcServerTargetURL()
	if err != nil {
		return nil, err
	}

	dialOptions := []grpc.DialOption{
		gw.grpcCallOpts(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	authority := gw.GetConfig().CoProcessOptions.GRPCAuthority
	if authority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(authority))
	}

	target := GetCoProcessGrpcServerTargetUrlAsString(grpcUrl)

	isRoundRobinEnabled := gw.GetConfig().CoProcessOptions.GRPCRoundRobinLoadBalancing
	if isRoundRobinEnabled {
		dialOptions = append(dialOptions, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))

		// Round-robin balances across whatever the resolver reports, and the
		// stock DNS resolver only re-resolves when a connection breaks — so a
		// pod added by a scale-up, which breaks nothing, is never discovered.
		// Swap in a resolver that polls, and address the client at it.
		if interval, pollEnabled := config.ResolveDNSRefreshInterval(gw.GetConfig().CoProcessOptions.GRPCDNSRefreshInterval); pollEnabled {
			endpoint, ok := bareGRPCEndpoint(target)
			if !ok {
				// Leave the client on the stock resolver rather than guessing.
				// Losing pod discovery is recoverable; failing to build the
				// dispatcher takes every plugin down with it.
				log.WithFields(logrus.Fields{
					"prefix": "coprocess",
					"target": target,
				}).Warning("Could not read a host:port from coprocess_grpc_server; gRPC plugin pod discovery disabled")
			} else {
				dialOptions = append(dialOptions, grpc.WithResolvers(&grpcresolver.Builder{
					Interval: interval,
					Ctx:      gw.ctx,
				}))
				target = grpcresolver.Target(endpoint)

				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"target":   target,
					"interval": interval.String(),
				}).Info("gRPC plugin pod discovery enabled")
			}
		}
	}

	grpcConnection, err = grpc.NewClient(
		target,
		dialOptions...,
	)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
		return nil, err
	}

	grpcClient = coprocess.NewDispatcherClient(grpcConnection)
	return &GRPCDispatcher{}, nil
}

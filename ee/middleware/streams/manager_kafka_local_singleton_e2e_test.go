package streams

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gorilla/mux"
	redis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/TykTechnologies/tyk/config"
)

func TestManagerLocalRoutingSingletonRealRedisE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = container.Terminate(cleanup)
	})
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	addr := net.JoinHostPort(host, port.Port())
	newManager := func(client *redis.Client) *Manager {
		gw := &kafkaProvisioningGateway{conf: config.Config{Secret: "local-singleton-manager-secret-at-least-32-bytes"}, client: client}
		mw := &Middleware{Spec: &APISpec{APIID: "singleton-api"}, Gw: gw, base: kafkaProvisioningBase{logger: logrus.New().WithField("test", "local-singleton")}}
		return &Manager{muxer: mux.NewRouter(), mw: mw, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	}
	newStream := func() map[string]interface{} {
		return map[string]interface{}{"input": map[string]interface{}{"tyk_kafka": map[string]interface{}{"seed_brokers": []interface{}{"unused:9092"}, "topics": []interface{}{"employees"}, "consumer_group": "workers", "acknowledgment": map[string]interface{}{"mode": "external_ack", "routing": "local", "component_id": "input"}}}, "output": map[string]interface{}{"http_server": map[string]interface{}{"path": "/out"}}}
	}
	hasLease := func(m *Manager) bool { _, ok := m.localSingletonLeases.Load("singleton-api_employees"); return ok }
	client1 := redis.NewClient(&redis.Options{Addr: addr})
	client2 := redis.NewClient(&redis.Options{Addr: addr})
	client3 := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client1.Close(); _ = client2.Close(); _ = client3.Close() })
	first, second := newManager(client1), newManager(client2)
	first.setUpOrDryRunStream(newStream(), "employees")
	require.True(t, hasLease(first), "first Manager did not acquire local singleton")
	second.setUpOrDryRunStream(newStream(), "employees")
	require.False(t, hasLease(second), "second Manager provisioned while first lease was live")
	first.removeTransportRegistrations("singleton-api_employees")
	second.setUpOrDryRunStream(newStream(), "employees")
	require.True(t, hasLease(second), "second Manager did not provision after first unload released the lease")

	// Closing only the owning Manager's Redis connection models abrupt process
	// loss: no explicit lease deletion occurs, and takeover waits for TTL expiry.
	require.NoError(t, client2.Close())
	third := newManager(client3)
	third.setUpOrDryRunStream(newStream(), "employees")
	require.False(t, hasLease(third), "crash lease was taken before expiry")
	require.Eventually(t, func() bool { third.setUpOrDryRunStream(newStream(), "employees"); return hasLease(third) }, 22*time.Second, 500*time.Millisecond, fmt.Sprintf("third Manager did not take over %s after crash TTL", addr))
	third.removeTransportRegistrations("singleton-api_employees")
	second.removeTransportRegistrations("singleton-api_employees")
}

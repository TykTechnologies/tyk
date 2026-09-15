package streams

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	redis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
	internalredis "github.com/TykTechnologies/tyk/internal/redis"
)

func TestManagerAcknowledgmentRateLimitWiring(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = redisClient.Close() })
	gateway := &kafkaProvisioningGateway{conf: config.Config{Secret: "manager-rate-limit-secret-at-least-32-bytes"}, client: redisClient}
	gateway.conf.KafkaControlRateLimits.AcknowledgmentRequestsPerSecond = 1
	gateway.conf.KafkaControlRateLimits.AcknowledgmentBurst = 1
	middleware := &Middleware{Spec: &APISpec{APIID: "rate-api"}, Gw: gateway, base: kafkaProvisioningBase{logger: logrus.New().WithField("test", "rate-limit")}}
	manager := &Manager{muxer: mux.NewRouter(), mw: middleware, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	ack := map[string]interface{}{"mode": "external_ack"}
	stream := map[string]interface{}{
		"input":  map[string]interface{}{"tyk_kafka": map[string]interface{}{"seed_brokers": []interface{}{"unused:9092"}, "topics": []interface{}{"employees"}, "consumer_group": "workers", "acknowledgment": ack}},
		"output": map[string]interface{}{"http_server": map[string]interface{}{"path": "/out"}},
	}
	manager.setUpOrDryRunStream(stream, "employees")
	componentID := ack["component_id"].(string)
	t.Cleanup(func() {
		manager.closeTransportRegistrations()
		kafka.GlobalRuntimeAckKeyRegistry.Remove(componentID)
	})

	post := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		manager.muxer.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`)))
		return rr
	}
	require.Equal(t, http.StatusBadRequest, post("/employees/kafka/ack").Code)
	limited := post("/employees/kafka/" + componentID + "/ack")
	require.Equal(t, http.StatusTooManyRequests, limited.Code, "aliases must share the configured bucket")
	require.Equal(t, "1", limited.Header().Get("Retry-After"))

	// Existing handlers read current config. Reconfiguration preserves the
	// exhausted bucket instead of granting a fresh burst.
	gateway.conf.KafkaControlRateLimits.AcknowledgmentRequestsPerSecond = 1_000_000 // clamped to the documented maximum
	gateway.conf.KafkaControlRateLimits.AcknowledgmentBurst = 1_000_000
	require.Equal(t, http.StatusTooManyRequests, post("/employees/kafka/ack").Code)
	time.Sleep(2 * time.Millisecond)
	require.Equal(t, http.StatusBadRequest, post("/employees/kafka/ack").Code, "live config was not applied to the existing handler")
}

func TestManagerSigningKeyUnloadAndStaleReloadCleanup(t *testing.T) {
	t.Run("failed setup rollback", func(t *testing.T) {
		componentID := "manager-key-failed-setup"
		provider, err := kafka.NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("manager-failed-setup-secret-value")})
		require.NoError(t, err)
		lease, err := kafka.GlobalRuntimeAckKeyRegistry.ConfigureRegistrationWithInvalidation(componentID, provider, true)
		require.NoError(t, err)
		manager := &Manager{}
		manager.keyRegistrations.Store("failed_stream", []*kafka.RuntimeAckKeyRegistration{lease})
		// This is the same deferred rollback invoked by setUpOrDryRunStream
		// whenever setupSucceeded remains false.
		manager.removeTransportRegistrations("failed_stream")
		_, err = kafka.GlobalRuntimeAckKeyRegistry.Resolve(context.Background(), componentID, "scope")
		require.Error(t, err)
	})

	componentID := "manager-key-lifecycle-component"
	provider1, err := kafka.NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("manager-key-lifecycle-secret-one!")})
	require.NoError(t, err)
	oldLease, err := kafka.GlobalRuntimeAckKeyRegistry.ConfigureRegistrationWithInvalidation(componentID, provider1, true)
	require.NoError(t, err)
	oldManager := &Manager{}
	oldManager.keyRegistrations.Store("api_stream", []*kafka.RuntimeAckKeyRegistration{oldLease})

	provider2, err := kafka.NewSharedAckSigningKeyProvider("v2", map[string][]byte{"v2": []byte("manager-key-lifecycle-secret-two!")})
	require.NoError(t, err)
	newLease, err := kafka.GlobalRuntimeAckKeyRegistry.ConfigureRegistrationWithInvalidation(componentID, provider2, true)
	require.NoError(t, err)
	newManager := &Manager{}
	newManager.keyRegistrations.Store("api_stream", []*kafka.RuntimeAckKeyRegistration{newLease})

	oldManager.removeTransportRegistrations("api_stream")
	_, err = kafka.GlobalRuntimeAckKeyRegistry.Resolve(context.Background(), componentID, "scope")
	require.NoError(t, err, "stale reload teardown removed replacement signing keys")
	newManager.removeTransportRegistrations("api_stream")
	_, err = kafka.GlobalRuntimeAckKeyRegistry.Resolve(context.Background(), componentID, "scope")
	require.Error(t, err, "current unload retained signing secrets")
}

type kafkaProvisioningGateway struct {
	conf   config.Config
	client internalredis.UniversalClient
}

func (g *kafkaProvisioningGateway) GetConfig() config.Config { return g.conf }
func (g *kafkaProvisioningGateway) ReplaceTykVariables(_ *http.Request, value string, _ bool) string {
	return value
}
func (g *kafkaProvisioningGateway) StreamingRedisClient() (internalredis.UniversalClient, error) {
	return g.client, nil
}

type kafkaProvisioningBase struct{ logger *logrus.Entry }

func (b kafkaProvisioningBase) Logger() *logrus.Entry { return b.logger }

func TestManagerProvisionsDefaultDistributedAcknowledgmentRouting(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = redisClient.Close() })
	gateway := &kafkaProvisioningGateway{conf: config.Config{Secret: "manager-provisioning-secret-at-least-32-bytes"}, client: redisClient}
	middleware := &Middleware{Spec: &APISpec{APIID: "api-default-routing"}, Gw: gateway, base: kafkaProvisioningBase{logger: logrus.New().WithField("test", "provisioning")}}
	manager := &Manager{muxer: mux.NewRouter(), mw: middleware, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	ack := map[string]interface{}{"mode": "external_ack"} // routing intentionally omitted
	stream := map[string]interface{}{
		"input": map[string]interface{}{"tyk_kafka": map[string]interface{}{"seed_brokers": []interface{}{"unused:9092"}, "topics": []interface{}{"employees"}, "consumer_group": "workers", "acknowledgment": ack}},
		// An HTTP path keeps dry-run provisioning from connecting to Kafka.
		"output": map[string]interface{}{"http_server": map[string]interface{}{"path": "/out"}},
	}
	manager.setUpOrDryRunStream(stream, "employees")
	componentID, ok := ack["component_id"].(string)
	require.True(t, ok)
	require.NotEmpty(t, componentID)
	t.Cleanup(func() {
		manager.closeTransportRegistrations()
		kafka.GlobalRuntimeAckKeyRegistry.Remove(componentID)
	})
	_, err := kafka.GlobalRuntimeAckTransportRegistry.Resolve(t.Context(), componentID)
	require.NoError(t, err, "omitted routing must provision the default distributed transport")
	resetStore, err := kafka.GlobalRuntimeResetStateStoreRegistry.Resolve(t.Context(), componentID)
	require.NoError(t, err, "Manager must provision reset persistence from the same Gateway Redis lifecycle")
	require.IsType(t, &kafka.RedisResetStateStore{}, resetStore)
	_, err = kafka.GlobalRuntimeAckKeyRegistry.Resolve(t.Context(), componentID, "scope")
	require.NoError(t, err, "Manager must provision signing keys in the same lifecycle")
	require.True(t, manager.hasPath("/employees/kafka/ack"), "control routes are provisioned with the default")
	manager.closeTransportRegistrations()
	_, err = kafka.GlobalRuntimeAckTransportRegistry.Resolve(t.Context(), componentID)
	require.Error(t, err, "Manager teardown removes its transport registration")
	_, err = kafka.GlobalRuntimeResetStateStoreRegistry.Resolve(t.Context(), componentID)
	require.Error(t, err, "Manager teardown removes its reset-store registration")
}

func TestManagerRejectsExternalAcknowledgmentWithWeakGatewaySecret(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = redisClient.Close() })
	gateway := &kafkaProvisioningGateway{conf: config.Config{Secret: "weak-secret"}, client: redisClient}
	middleware := &Middleware{Spec: &APISpec{APIID: "api-weak-signing"}, Gw: gateway, base: kafkaProvisioningBase{logger: logrus.New().WithField("test", "weak-signing")}}
	manager := &Manager{muxer: mux.NewRouter(), mw: middleware, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	ack := map[string]interface{}{"mode": "external_ack"}
	stream := map[string]interface{}{
		"input":  map[string]interface{}{"tyk_kafka": map[string]interface{}{"seed_brokers": []interface{}{"unused:9092"}, "topics": []interface{}{"employees"}, "consumer_group": "workers", "acknowledgment": ack}},
		"output": map[string]interface{}{"http_server": map[string]interface{}{"path": "/out"}},
	}
	manager.setUpOrDryRunStream(stream, "employees")
	componentID := ack["component_id"].(string)
	t.Cleanup(func() {
		manager.closeTransportRegistrations()
		kafka.GlobalRuntimeAckKeyRegistry.Remove(componentID)
	})
	_, err := kafka.GlobalRuntimeAckKeyRegistry.Resolve(t.Context(), componentID, "scope")
	require.Error(t, err, "weak fallback must never register acknowledgment signing keys")
	_, err = kafka.GlobalRuntimeAckTransportRegistry.Resolve(t.Context(), componentID)
	require.Error(t, err, "failed signing setup must roll back distributed transport provisioning")
	require.False(t, manager.hasPath("/employees/kafka/ack"), "rejected streams must not expose an acknowledgment endpoint")
}

func TestManagerRollsBackTransportWhenResetStoreRegistrationFails(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = redisClient.Close() })
	const componentID = "manager-reset-collision"
	occupied, err := kafka.GlobalRuntimeResetStateStoreRegistry.Configure(componentID, kafka.StaticResetStateStoreProvider{Store: kafka.NewInMemoryResetStateStore()})
	require.NoError(t, err)
	t.Cleanup(func() { occupied.Remove() })
	gateway := &kafkaProvisioningGateway{conf: config.Config{Secret: "manager-provisioning-secret-at-least-32-bytes"}, client: redisClient}
	middleware := &Middleware{Spec: &APISpec{APIID: "api-reset-rollback"}, Gw: gateway, base: kafkaProvisioningBase{logger: logrus.New().WithField("test", "reset-rollback")}}
	manager := &Manager{muxer: mux.NewRouter(), mw: middleware, background: true, analyticsFactory: &NoopStreamAnalyticsFactory{}}
	ack := map[string]interface{}{"mode": "external_ack", "component_id": componentID}
	stream := map[string]interface{}{
		"input":  map[string]interface{}{"tyk_kafka": map[string]interface{}{"seed_brokers": []interface{}{"unused:9092"}, "topics": []interface{}{"employees"}, "consumer_group": "workers", "acknowledgment": ack}},
		"output": map[string]interface{}{"http_server": map[string]interface{}{"path": "/out"}},
	}
	manager.setUpOrDryRunStream(stream, "employees")
	_, err = kafka.GlobalRuntimeAckTransportRegistry.Resolve(t.Context(), componentID)
	require.Error(t, err, "reset-store failure must atomically roll back the paired acknowledgment transport")
}

package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	dockerclient "github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/warpstreamlabs/bento/public/service"
)

func TestExternalAcknowledgmentKafkaOutageLifecycleE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	docker, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer docker.Close()
	paused := false
	pause := func() { require.NoError(t, docker.ContainerPause(ctx, container.GetContainerID())); paused = true }
	unpause := func() {
		if paused {
			require.NoError(t, docker.ContainerUnpause(ctx, container.GetContainerID()))
			paused = false
		}
	}
	t.Cleanup(unpause)
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	defer producer.Close()

	runStream := func(topic, group, component string) (*service.Stream, *sync.Mutex, *string) {
		var mu sync.Mutex
		token := ""
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			token = r.Header.Get("Tyk-Kafka-Ack-Token")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(downstream.Close)
		provider, providerErr := NewSharedAckSigningKeyProvider("outage-v1", map[string][]byte{"outage-v1": []byte("kafka-outage-lifecycle-shared-secret")})
		require.NoError(t, providerErr)
		require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(component, provider))
		t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(component) })
		builder := service.NewStreamBuilder()
		require.NoError(t, builder.SetYAML(fmt.Sprintf(`
input:
  tyk_kafka:
    seed_brokers: [%q]
    topics: [%q]
    consumer_group: %q
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 2
      max_in_flight: 2
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
`, brokers[0], topic, group, component, downstream.URL)))
		stream, buildErr := builder.Build()
		require.NoError(t, buildErr)
		go func() {
			if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
				t.Errorf("stream failed: %v", runErr)
			}
		}()
		return stream, &mu, &token
	}
	ack := func(component, token string) int {
		handler := NewAcknowledgmentHandler(GlobalControllerRegistry, ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}, HandlerLimits{})
		request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	topic, group, component := "outage-"+suffix, "outage-group-"+suffix, "outage-component-"+suffix
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("commit-during-outage")})
	require.NoError(t, err)
	stream, mu, token := runStream(topic, group, component)
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return *token != "" }, 30*time.Second, 100*time.Millisecond)
	mu.Lock()
	firstToken := *token
	mu.Unlock()
	pause()
	started := time.Now()
	require.Equal(t, http.StatusServiceUnavailable, ack(component, firstToken))
	require.Less(t, time.Since(started), 12*time.Second, "commit failure must be bounded")
	unpause()
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	defer client.Close()
	// A timed-out Kafka commit is intentionally treated as an ambiguous result:
	// the coordinator may have applied it while the response was unavailable.
	// Both observable states are safe because retrying the same next offset is
	// idempotent and can never skip beyond this delivery.
	afterFailure := fetchCommittedOffset(t, client, group, topic, 0)
	require.Contains(t, []int64{-1, 1}, afterFailure)
	t.Logf("offset after unavailable commit response: %d", afterFailure)
	require.Eventually(t, func() bool { return ack(component, firstToken) == http.StatusOK }, 20*time.Second, 250*time.Millisecond, "idempotent retry did not commit after broker recovery")
	require.Eventually(t, func() bool { return fetchCommittedOffset(t, client, group, topic, 0) == 1 }, 10*time.Second, 100*time.Millisecond)
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("shutdown-while-down")})
	require.NoError(t, err)
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return *token != "" && *token != firstToken }, 20*time.Second, 100*time.Millisecond)
	pause()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	shutdownStarted := time.Now()
	_ = stream.Stop(stopCtx)
	stopCancel()
	require.Less(t, time.Since(shutdownStarted), 4*time.Second, "shutdown blocked on unavailable broker")
	unpause()

	startupTopic, startupGroup, startupComponent := "startup-"+suffix, "startup-group-"+suffix, "startup-component-"+suffix
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: startupTopic, Value: sarama.StringEncoder("startup-recovery")})
	require.NoError(t, err)
	pause()
	startupStream, startupMu, startupToken := runStream(startupTopic, startupGroup, startupComponent)
	require.Never(t, func() bool { startupMu.Lock(); defer startupMu.Unlock(); return *startupToken != "" }, time.Second, 100*time.Millisecond)
	unpause()
	require.Eventually(t, func() bool { startupMu.Lock(); defer startupMu.Unlock(); return *startupToken != "" }, 30*time.Second, 100*time.Millisecond, "connector did not recover after unavailable startup")
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finalCancel()
	require.NoError(t, startupStream.Stop(finalCtx))
}

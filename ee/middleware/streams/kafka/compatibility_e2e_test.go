package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/warpstreamlabs/bento/public/service"
)

// TYK_KAFKA_COMPAT_IMAGES allows release CI to replace or extend the default
// representative matrix without duplicating the acceptance scenario.
func kafkaCompatibilityImages() []string {
	if configured := strings.TrimSpace(os.Getenv("TYK_KAFKA_COMPAT_IMAGES")); configured != "" {
		var result []string
		for _, image := range strings.Split(configured, ",") {
			if image = strings.TrimSpace(image); image != "" {
				result = append(result, image)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return []string{"confluentinc/confluent-local:7.5.0", "confluentinc/confluent-local:7.8.0"}
}

func TestExternalAcknowledgmentKafkaCompatibilityMatrixE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	for _, image := range kafkaCompatibilityImages() {
		image := image
		t.Run(strings.NewReplacer("/", "_", ":", "_").Replace(image), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			container, err := tckafka.Run(ctx, image)
			require.NoError(t, err)
			t.Cleanup(func() { _ = container.Terminate(context.Background()) })
			brokers, err := container.Brokers(ctx)
			require.NoError(t, err)

			suffix := fmt.Sprintf("%d", time.Now().UnixNano())
			topic, group, component := "compat-topic-"+suffix, "compat-group-"+suffix, "compat-component-"+suffix
			cfg := sarama.NewConfig()
			cfg.Version, cfg.Producer.Return.Successes = sarama.V2_0_0_0, true
			producer, err := sarama.NewSyncProducer(brokers, cfg)
			require.NoError(t, err)
			defer producer.Close()
			_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("compatibility-event")})
			require.NoError(t, err)

			var mu sync.Mutex
			token := ""
			downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				token = r.Header.Get("Tyk-Kafka-Ack-Token")
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer downstream.Close()
			provider, err := NewSharedAckSigningKeyProvider("matrix-v1", map[string][]byte{"matrix-v1": []byte("compatibility-matrix-shared-secret")})
			require.NoError(t, err)
			require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(component, provider))
			defer GlobalRuntimeAckKeyRegistry.Remove(component)
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
      checkpoint_limit: 1
      max_in_flight: 1
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
`, brokers[0], topic, group, component, downstream.URL)))
			stream, err := builder.Build()
			require.NoError(t, err)
			go func() {
				if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
					t.Errorf("stream failed for %s: %v", image, runErr)
				}
			}()
			defer func() {
				stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				_ = stream.Stop(stopCtx)
			}()
			require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return token != "" }, 30*time.Second, 100*time.Millisecond)
			client, err := sarama.NewClient(brokers, cfg)
			require.NoError(t, err)
			defer client.Close()
			require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0))
			mu.Lock()
			deliveryToken := token
			mu.Unlock()
			handler := NewAcknowledgmentHandler(GlobalControllerRegistry, ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}, HandlerLimits{})
			request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, deliveryToken)))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			require.Eventually(t, func() bool { return fetchCommittedOffset(t, client, group, topic, 0) == 1 }, 15*time.Second, 100*time.Millisecond)
		})
	}
}

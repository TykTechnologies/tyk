package kafka

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

// TestKafkaAcknowledgmentPerformanceE2E is an opt-in comparative acceptance
// harness, not a microbenchmark. Enable with TYK_KAFKA_PERF=1. The optional
// TYK_KAFKA_PERF_MIN_RPS applies the same explicit operator SLO to every mode;
// no repository default is treated as a release threshold.
func TestKafkaAcknowledgmentPerformanceE2E(t *testing.T) {
	if testing.Short() || os.Getenv("TYK_KAFKA_PERF") == "" {
		t.Skip("set TYK_KAFKA_PERF=1; requires Docker")
	}
	records := 1000
	if raw := os.Getenv("TYK_KAFKA_PERF_RECORDS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		require.NoError(t, err)
		require.Positive(t, parsed)
		records = parsed
	}
	minRPS := 0.0
	if raw := os.Getenv("TYK_KAFKA_PERF_MIN_RPS"); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		require.NoError(t, err)
		require.Positive(t, parsed)
		minRPS = parsed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() {
		c, x := context.WithTimeout(context.Background(), 15*time.Second)
		defer x()
		_ = container.Terminate(c)
	})
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	results := map[string]float64{}
	for _, mode := range []string{"stock_output_ack", "tyk_output_ack", "tyk_external_ack"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			rps := runKafkaPerformanceCase(t, ctx, brokers[0], mode, records)
			results[mode] = rps
			t.Logf("mode=%s records=%d records_per_second=%.2f", mode, records, rps)
			if minRPS > 0 {
				require.GreaterOrEqual(t, rps, minRPS, "operator-configured throughput SLO")
			}
		})
	}
	if raw := os.Getenv("TYK_KAFKA_PERF_MIN_EXTERNAL_RATIO"); raw != "" {
		minimum, err := strconv.ParseFloat(raw, 64)
		require.NoError(t, err)
		require.Positive(t, minimum)
		ratio := results["tyk_external_ack"] / results["stock_output_ack"]
		t.Logf("external_to_stock_ratio=%.3f", ratio)
		require.GreaterOrEqual(t, ratio, minimum, "operator-configured external/stock throughput ratio SLO")
	}
}

func runKafkaPerformanceCase(t *testing.T, ctx context.Context, broker, mode string, records int) float64 {
	t.Helper()
	topic := fmt.Sprintf("perf-%s-%d", mode, time.Now().UnixNano())
	group := topic + "-group"
	component := topic + "-component"
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_8_0_0
	cfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer([]string{broker}, cfg)
	require.NoError(t, err)
	defer producer.Close()
	messages := make([]*sarama.ProducerMessage, records)
	for i := range messages {
		messages[i] = &sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder(fmt.Sprintf("event-%d", i))}
	}
	require.NoError(t, producer.SendMessages(messages))
	observer, err := sarama.NewClient([]string{broker}, cfg)
	require.NoError(t, err)
	defer observer.Close()
	var delivered atomic.Int64
	var handler http.Handler
	ackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler == nil {
			http.Error(w, "handler unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer ackServer.Close()
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if mode == "tyk_external_ack" {
			token := r.Header.Get("Tyk-Kafka-Ack-Token")
			if token == "" || handler == nil {
				http.Error(w, "token unavailable", 500)
				return
			}
			response, err := http.Post(ackServer.URL, "application/json", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			responseBody, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				http.Error(w, string(responseBody), response.StatusCode)
				return
			}
		}
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	inputName := "kafka_franz"
	ackConfig := ""
	if mode != "stock_output_ack" {
		inputName = "tyk_kafka"
	}
	if mode == "tyk_external_ack" {
		provider, err := NewSharedAckSigningKeyProvider("perf-v1", map[string][]byte{"perf-v1": []byte("performance-e2e-shared-signing-secret")})
		require.NoError(t, err)
		require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(component, provider))
		defer GlobalRuntimeAckKeyRegistry.Remove(component)
		handler = NewAcknowledgmentHandler(GlobalControllerRegistry, ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}, HandlerLimits{})
		ackConfig = fmt.Sprintf("\n    acknowledgment:\n      mode: external_ack\n      component_id: %q\n      checkpoint_limit: 1024\n      max_in_flight: 4096\n      max_in_flight_bytes: 64MiB\n      commit_interval: 100ms\n      routing: local", component)
	}
	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf("input:\n  %s:\n    seed_brokers: [%q]\n    topics: [%q]\n    consumer_group: %q\n    commit_period: 100ms%s\noutput:\n  http_client:\n    url: %q\n    verb: POST\n    max_in_flight: 64\n    headers:\n      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'\n", inputName, broker, topic, group, ackConfig, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	started := time.Now()
	go func() { _ = stream.Run(runCtx) }()
	defer func() {
		c, x := context.WithTimeout(context.Background(), 10*time.Second)
		defer x()
		_ = stream.Stop(c)
	}()
	require.Eventually(t, func() bool { return delivered.Load() == int64(records) }, 2*time.Minute, 20*time.Millisecond)
	require.Eventually(t, func() bool { return fetchCommittedOffset(t, observer, group, topic, 0) == int64(records) }, 30*time.Second, 20*time.Millisecond, "delivery completed without durable group progress")
	return float64(records) / time.Since(started).Seconds()
}

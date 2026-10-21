package kafka

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

// TestExternalAcknowledgmentKafkaSASLE2E proves that authentication is applied
// to the actual external-ack connector, rather than merely to an administrative
// probe. Each case produces through SASL, delivers through tyk_kafka to a real
// TCP HTTP server, acknowledges the signed delivery token, and observes the
// consumer-group commit through SASL.
func TestExternalAcknowledgmentKafkaSASLE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	mechanisms, err := kafkaSecurityMechanisms(os.Getenv("TYK_KAFKA_SECURITY_MECHANISM"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	jaasPath := filepath.Join(t.TempDir(), "kafka-server-jaas.conf")
	require.NoError(t, os.WriteFile(jaasPath, []byte(`KafkaServer {
  org.apache.kafka.common.security.plain.PlainLoginModule required
  username="broker"
  password="broker-secret"
  user_client="client-secret";
};
`), 0o600))

	t.Log("starting secured Kafka container")
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0",
		testcontainers.WithEnv(map[string]string{
			"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP":                             "BROKER:PLAINTEXT,PLAINTEXT:SASL_PLAINTEXT,CONTROLLER:PLAINTEXT",
			"KAFKA_SASL_ENABLED_MECHANISMS":                                    "PLAIN,SCRAM-SHA-256,SCRAM-SHA-512",
			"KAFKA_LISTENER_NAME_PLAINTEXT_PLAIN_SASL_JAAS_CONFIG":             `org.apache.kafka.common.security.plain.PlainLoginModule required username="broker" password="broker-secret" user_client="client-secret";`,
			"KAFKA_LISTENER_NAME_PLAINTEXT_SCRAM___SHA___256_SASL_JAAS_CONFIG": "org.apache.kafka.common.security.scram.ScramLoginModule required;",
			"KAFKA_LISTENER_NAME_PLAINTEXT_SCRAM___SHA___512_SASL_JAAS_CONFIG": "org.apache.kafka.common.security.scram.ScramLoginModule required;",
			"KAFKA_OPTS": "-Djava.security.auth.login.config=/etc/kafka/secrets/tyk-kafka-server-jaas.conf",
		}),
		testcontainers.WithMounts(testcontainers.BindMount(jaasPath, testcontainers.ContainerMountTarget("/etc/kafka/secrets/tyk-kafka-server-jaas.conf"))),
	)
	require.NoError(t, err)
	t.Log("secured Kafka container started")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		require.NoError(t, container.Terminate(cleanupCtx))
	})
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	t.Logf("secured Kafka external listener: %s", brokers[0])

	selectedMechanism := strings.TrimSpace(os.Getenv("TYK_KAFKA_SECURITY_MECHANISM"))
	for _, mechanism := range []string{"SCRAM-SHA-256", "SCRAM-SHA-512"} {
		if selectedMechanism == "PLAIN" {
			break
		}
		t.Logf("installing %s credential", mechanism)
		execCtx, execCancel := context.WithTimeout(ctx, 15*time.Second)
		code, output, execErr := container.Exec(execCtx, []string{
			"kafka-configs", "--bootstrap-server", "localhost:9092", "--alter",
			"--add-config", mechanism + "=[password=client-secret]",
			"--entity-type", "users", "--entity-name", "client",
		})
		body, _ := io.ReadAll(output)
		execCancel()
		require.NoError(t, execErr, "%s credential command: %s", mechanism, body)
		require.Equal(t, 0, code, "%s credential command: %s", mechanism, body)
		t.Logf("installed %s credential", mechanism)
	}

	for _, mechanism := range mechanisms {
		mechanism := mechanism
		t.Run(mechanism, func(t *testing.T) {
			runExternalAckSASLCase(t, ctx, brokers, mechanism)
		})
	}
}

func kafkaSecurityMechanisms(configured string) ([]string, error) {
	all := []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return all, nil
	}
	for _, mechanism := range all {
		if configured == mechanism {
			return []string{mechanism}, nil
		}
	}
	return nil, fmt.Errorf("unsupported TYK_KAFKA_SECURITY_MECHANISM %q", configured)
}

func runExternalAckSASLCase(t *testing.T, ctx context.Context, brokers []string, mechanism string) {
	t.Helper()
	topic := fmt.Sprintf("external-ack-security-%s-%d", strings.ToLower(strings.ReplaceAll(mechanism, "-", "")), time.Now().UnixNano())
	group := fmt.Sprintf("external-ack-security-group-%d", time.Now().UnixNano())
	componentID := fmt.Sprintf("external-ack-security-%s-%d", strings.ToLower(mechanism), time.Now().UnixNano())

	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_8_0_0
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Net.DialTimeout = 5 * time.Second
	saramaConfig.Net.ReadTimeout = 5 * time.Second
	saramaConfig.Net.WriteTimeout = 5 * time.Second
	saramaConfig.Metadata.Timeout = 5 * time.Second
	saramaConfig.Metadata.Retry.Max = 2
	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = "client"
	saramaConfig.Net.SASL.Password = "client-secret"
	switch mechanism {
	case "PLAIN":
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	case "SCRAM-SHA-256":
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA256} }
	case "SCRAM-SHA-512":
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA512} }
	}
	t.Log("connecting authenticated producer")
	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { boundedSecurityClose(t, "producer", producer.Close) })
	t.Log("producing secured event")
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("secured-event")})
	require.NoError(t, err)
	t.Log("secured event produced")

	var mu sync.Mutex
	var token, delivered string
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		token = r.Header.Get("Tyk-Kafka-Ack-Token")
		delivered = string(payload)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)

	keyProvider, err := NewSharedAckSigningKeyProvider("security-v1", map[string][]byte{"security-v1": []byte("external-ack-security-shared-secret")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, keyProvider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(componentID) })

	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf(`
input:
  tyk_kafka:
    seed_brokers: [%q]
    topics: [%q]
    consumer_group: %q
    sasl:
      - mechanism: %q
        username: client
        password: client-secret
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
`, brokers[0], topic, group, mechanism, componentID, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	t.Log("starting tyk_kafka connector")
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() {
		if runErr := stream.Run(runCtx); runErr != nil && runCtx.Err() == nil {
			t.Errorf("secured stream failed: %v", runErr)
		}
	}()
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = stream.Stop(stopCtx)
	})
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return token != "" && delivered == "secured-event"
	}, 30*time.Second, 100*time.Millisecond)
	t.Log("connector delivered secured event and token")

	t.Log("connecting authenticated offset observer")
	client, err := sarama.NewClient(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { boundedSecurityClose(t, "offset observer", client.Close) })
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0))
	mu.Lock()
	ackToken := token
	mu.Unlock()
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}, HandlerLimits{})
	request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, ackToken)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	t.Log("acknowledgment accepted; awaiting Kafka commit")
	require.Eventually(t, func() bool {
		return fetchCommittedOffset(t, client, group, topic, 0) == 1
	}, 10*time.Second, 100*time.Millisecond)
	t.Log("Kafka committed offset 1")
}

func boundedSecurityClose(t *testing.T, name string, closeFn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	select {
	case err := <-done:
		require.NoError(t, err, "close %s", name)
	case <-time.After(10 * time.Second):
		t.Errorf("timed out closing %s", name)
	}
}

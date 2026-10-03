package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

func TestExternalAcknowledgmentE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	image := strings.TrimSpace(os.Getenv("TYK_KAFKA_COMPAT_IMAGE"))
	if image == "" {
		image = "confluentinc/confluent-local:7.5.0"
	}
	t.Logf("Kafka compatibility image: %s", image)
	container, err := tckafka.Run(ctx, image)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)

	topic := fmt.Sprintf("external-ack-%d", time.Now().UnixNano())
	group := fmt.Sprintf("external-ack-group-%d", time.Now().UnixNano())
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0
	saramaConfig.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })
	for i := 0; i < 4; i++ {
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder(fmt.Sprintf("event-%d", i))})
		require.NoError(t, err)
	}

	var (
		mu     sync.Mutex
		tokens = map[int64]string{}
	)
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		offset, parseErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Offset"), 10, 64)
		if parseErr != nil {
			http.Error(w, "missing offset", http.StatusBadRequest)
			return
		}
		mu.Lock()
		tokens[offset] = r.Header.Get("Tyk-Kafka-Ack-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)

	componentID := "external-ack-e2e"
	keyProvider, err := NewSharedAckSigningKeyProvider("test-v1", map[string][]byte{"test-v1": []byte("external-ack-e2e-shared-secret-0001")})
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
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 3
      max_in_flight: 3
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
      Tyk-Kafka-Offset: '${! @kafka_offset }'
`, brokers[0], topic, group, componentID, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	go func() {
		if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
			t.Errorf("stream failed: %v", runErr)
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
		return len(tokens) == 3 && tokens[0] != "" && tokens[1] != "" && tokens[2] != ""
	}, 30*time.Second, 100*time.Millisecond)
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	require.Len(t, tokens, 3, "a full manual-ack window must stop the fourth delivery without reconnecting")
	mu.Unlock()

	client, err := sarama.NewClient(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0))
	require.Never(t, func() bool {
		return fetchCommittedOffset(t, client, group, topic, 0) != -1
	}, 6*time.Second, 250*time.Millisecond, "franz-go periodic auto-commit bypassed external acknowledgment")

	key := ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, key, HandlerLimits{})
	ack := func(offset int64) *httptest.ResponseRecorder {
		mu.Lock()
		token := tokens[offset]
		mu.Unlock()
		request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	// Completing the highest record first cannot commit across the lower gap.
	require.Equal(t, http.StatusOK, ack(2).Code)
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0))
	require.Equal(t, http.StatusOK, ack(0).Code)
	require.Equal(t, int64(1), fetchCommittedOffset(t, client, group, topic, 0))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return tokens[3] != ""
	}, 10*time.Second, 50*time.Millisecond, "consumer did not resume after capacity was acknowledged")
	require.Equal(t, http.StatusOK, ack(1).Code)
	require.Equal(t, int64(3), fetchCommittedOffset(t, client, group, topic, 0))
	require.Equal(t, http.StatusOK, ack(3).Code)
	require.Equal(t, int64(4), fetchCommittedOffset(t, client, group, topic, 0))

	// Duplicate acknowledgments are idempotent.
	require.Equal(t, http.StatusOK, ack(1).Code)
}

func TestExternalAcknowledgmentRegexTopicLifecycleE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	topicA, topicB := "edge-a-"+suffix, "edge-b-"+suffix
	pattern := "edge-[ab]-" + suffix
	group, componentID := "edge-group-"+suffix, "edge-component-"+suffix
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	cfg.Producer.Partitioner = sarama.NewManualPartitioner
	admin, err := sarama.NewClusterAdmin(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	require.NoError(t, admin.CreateTopic(topicA, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })

	type observed struct {
		topic     string
		partition int32
		token     string
	}
	var mu sync.Mutex
	var deliveries []observed
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		partition, parseErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Partition"), 10, 32)
		if parseErr != nil {
			http.Error(w, "partition", http.StatusBadRequest)
			return
		}
		mu.Lock()
		deliveries = append(deliveries, observed{r.Header.Get("Tyk-Kafka-Topic"), int32(partition), r.Header.Get("Tyk-Kafka-Ack-Token")})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)
	keyProvider, err := NewSharedAckSigningKeyProvider("test-v1", map[string][]byte{"test-v1": []byte("regex-lifecycle-e2e-shared-secret")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, keyProvider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(componentID) })
	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf(`
input:
  tyk_kafka:
    seed_brokers: [%q]
    topics: [%q]
    regexp_topics: true
    metadata_max_age: 5s
    consumer_group: %q
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 8
      max_in_flight: 32
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
      Tyk-Kafka-Topic: '${! @kafka_topic }'
      Tyk-Kafka-Partition: '${! @kafka_partition }'
`, brokers[0], pattern, group, componentID, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	go func() {
		if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
			t.Errorf("stream failed: %v", runErr)
		}
	}()
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = stream.Stop(stopCtx)
	})
	key := ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, key, HandlerLimits{})
	ackObserved := func(targetTopic string, targetPartition int32) bool {
		mu.Lock()
		var token string
		for _, d := range deliveries {
			if d.topic == targetTopic && d.partition == targetPartition {
				token = d.token
			}
		}
		mu.Unlock()
		if token == "" {
			return false
		}
		req := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code == http.StatusOK
	}
	send := func(topic string, partition int32, value string) {
		_, _, sendErr := producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Partition: partition, Value: sarama.StringEncoder(value)})
		require.NoError(t, sendErr)
	}

	send(topicA, 0, "initial")
	require.Eventually(t, func() bool { return ackObserved(topicA, 0) }, 30*time.Second, 100*time.Millisecond)
	require.NoError(t, admin.CreatePartitions(topicA, 2, nil, false))
	require.NoError(t, producer.Close())
	producer, err = sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	send(topicA, 1, "expanded")
	require.Eventually(t, func() bool { return ackObserved(topicA, 1) }, 30*time.Second, 100*time.Millisecond, "expanded partition was not discovered")
	require.NoError(t, admin.CreateTopic(topicB, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
	send(topicB, 0, "regex-discovered")
	require.Eventually(t, func() bool { return ackObserved(topicB, 0) }, 30*time.Second, 100*time.Millisecond, "new regex topic was not discovered")
	require.NoError(t, admin.DeleteTopic(topicB))
	require.Eventually(t, func() bool {
		controllers, ok := GlobalControllerRegistry.lookup(key)
		if !ok || controllers.Status == nil {
			return false
		}
		status := controllers.Status.StatusSnapshot(16)
		for _, partition := range status.Partitions {
			if partition.Topic == topicB {
				return false
			}
		}
		return len(status.Partitions) <= 2
	}, 30*time.Second, 100*time.Millisecond, "deleted regex topic retained unbounded controller state")
}

type e2ePartitionKey struct {
	topic     string
	partition int32
}

type gatedAckTransport struct {
	DurableAckTransport
	drain <-chan struct{}
}

func (g *gatedAckTransport) Claim(ctx context.Context, assignment AckAssignment, consumer string, limit int, lease time.Duration, now time.Time) ([]AckDelivery, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.drain:
		return g.DurableAckTransport.Claim(ctx, assignment, consumer, limit, lease, now)
	}
}

func TestExternalAcknowledgmentDistributedKafkaRedisE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	kafkaContainer, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, kafkaContainer.Terminate(context.Background())) })
	brokers, err := kafkaContainer.Brokers(ctx)
	require.NoError(t, err)
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, redisContainer.Terminate(context.Background())) })
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	port, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	redisClient := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	t.Cleanup(func() { require.NoError(t, redisClient.Close()) })
	require.NoError(t, redisClient.Ping(ctx).Err())

	topic := fmt.Sprintf("distributed-ack-%d", time.Now().UnixNano())
	group := fmt.Sprintf("distributed-ack-group-%d", time.Now().UnixNano())
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("distributed-event")})
	require.NoError(t, err)
	var mu sync.Mutex
	token := ""
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		token = r.Header.Get("Tyk-Kafka-Ack-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)

	componentID := "distributed-ack-e2e"
	keyProvider, err := NewSharedAckSigningKeyProvider("test-v1", map[string][]byte{"test-v1": []byte("distributed-e2e-shared-signing-secret")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, keyProvider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(componentID) })
	redisTransport, err := NewRedisDurableAckTransport(redisClient, RedisDurableAckOptions{Prefix: "e2e:distributed", MaxEntries: 10, MaxBytes: 1 << 20})
	require.NoError(t, err)
	drain := make(chan struct{})
	gated := &gatedAckTransport{DurableAckTransport: redisTransport, drain: drain}
	transportRegistration, err := GlobalRuntimeAckTransportRegistry.Configure(componentID, StaticDurableAckTransportProvider{Transport: gated})
	require.NoError(t, err)
	t.Cleanup(func() { transportRegistration.Remove() })
	resetRegistration, err := GlobalRuntimeResetStateStoreRegistry.Configure(componentID, StaticResetStateStoreProvider{Store: NewInMemoryResetStateStore()})
	require.NoError(t, err)
	t.Cleanup(func() { resetRegistration.Remove() })
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
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
`, brokers[0], topic, group, componentID, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	go func() {
		if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
			t.Errorf("stream failed: %v", runErr)
		}
	}()
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = stream.Stop(stopCtx)
	})
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return token != "" }, 30*time.Second, 100*time.Millisecond)
	mu.Lock()
	deliveryToken := token
	mu.Unlock()
	key := ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, key, HandlerLimits{})
	post := func(value string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, value)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := post(deliveryToken)
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	route := AckRoute{Key: key, Topic: topic, Partition: 0}
	require.Equal(t, 1, redisTransport.Stats(ctx, route).Active, "202 must follow the durable Redis append")
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0), "gated owner has not drained Redis")
	response = post("not-a-signed-token")
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Equal(t, 1, redisTransport.Stats(ctx, route).Active, "invalid token must not be appended")
	close(drain)
	require.Eventually(t, func() bool {
		return fetchCommittedOffset(t, client, group, topic, 0) == 1 && redisTransport.Stats(ctx, route).Active == 0
	}, 15*time.Second, 100*time.Millisecond, "partition owner did not drain Redis and commit Kafka")
}

func TestExternalAcknowledgmentMultiTopicPartitionE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	topicA := fmt.Sprintf("external-ack-a-%d", time.Now().UnixNano())
	topicB := fmt.Sprintf("external-ack-b-%d", time.Now().UnixNano())
	group := fmt.Sprintf("external-ack-multi-group-%d", time.Now().UnixNano())
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	cfg.Producer.Partitioner = sarama.NewManualPartitioner
	admin, err := sarama.NewClusterAdmin(brokers, cfg)
	require.NoError(t, err)
	require.NoError(t, admin.CreateTopic(topicA, &sarama.TopicDetail{NumPartitions: 2, ReplicationFactor: 1}, false))
	require.NoError(t, admin.CreateTopic(topicB, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
	require.NoError(t, admin.Close())
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })
	produce := func(topic string, partition int32, count int) {
		for i := 0; i < count; i++ {
			_, _, sendErr := producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Partition: partition, Value: sarama.StringEncoder(fmt.Sprintf("%s-%d-%d", topic, partition, i))})
			require.NoError(t, sendErr)
		}
	}
	produce(topicA, 0, 3)
	produce(topicA, 1, 2)
	produce(topicB, 0, 2)

	var mu sync.Mutex
	tokens := map[e2ePartitionKey]map[int64]string{}
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		partition, pErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Partition"), 10, 32)
		offset, oErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Offset"), 10, 64)
		if pErr != nil || oErr != nil || r.Header.Get("Tyk-Kafka-Topic") == "" {
			http.Error(w, "missing Kafka identity", http.StatusBadRequest)
			return
		}
		key := e2ePartitionKey{r.Header.Get("Tyk-Kafka-Topic"), int32(partition)}
		mu.Lock()
		if tokens[key] == nil {
			tokens[key] = map[int64]string{}
		}
		tokens[key][offset] = r.Header.Get("Tyk-Kafka-Ack-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)
	componentID := "external-ack-multi-e2e"
	provider, err := NewSharedAckSigningKeyProvider("test-v1", map[string][]byte{"test-v1": []byte("external-ack-multi-shared-secret-0001")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, provider))
	t.Cleanup(func() { GlobalRuntimeAckKeyRegistry.Remove(componentID) })
	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf(`
input:
  tyk_kafka:
    seed_brokers: [%q]
    topics: [%q, %q]
    consumer_group: %q
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 2
      max_in_flight: 10
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
      Tyk-Kafka-Topic: '${! @kafka_topic }'
      Tyk-Kafka-Partition: '${! @kafka_partition }'
      Tyk-Kafka-Offset: '${! @kafka_offset }'
`, brokers[0], topicA, topicB, group, componentID, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	go func() {
		if runErr := stream.Run(ctx); runErr != nil && ctx.Err() == nil {
			t.Errorf("stream failed: %v", runErr)
		}
	}()
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = stream.Stop(stopCtx)
	})
	p0, p1, b0 := e2ePartitionKey{topicA, 0}, e2ePartitionKey{topicA, 1}, e2ePartitionKey{topicB, 0}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(tokens[p0]) == 2 && len(tokens[p1]) == 2 && len(tokens[b0]) == 2
	}, 30*time.Second, 100*time.Millisecond, "a full partition must not stall other topic/partitions")
	require.Never(t, func() bool { mu.Lock(); defer mu.Unlock(); return tokens[p0][2] != "" }, 750*time.Millisecond, 50*time.Millisecond, "partition 0 exceeded its independent checkpoint window")

	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	key := ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, key, HandlerLimits{})
	ack := func(partition e2ePartitionKey, offset int64) {
		mu.Lock()
		token := tokens[partition][offset]
		mu.Unlock()
		request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	}
	ack(p0, 1)
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topicA, 0))
	ack(p1, 1)
	require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topicA, 1))
	ack(b0, 0)
	require.Equal(t, int64(1), fetchCommittedOffset(t, client, group, topicB, 0), "another topic commits despite partition 0 being paused")
	ack(p1, 0)
	require.Equal(t, int64(2), fetchCommittedOffset(t, client, group, topicA, 1))
	ack(b0, 1)
	require.Equal(t, int64(2), fetchCommittedOffset(t, client, group, topicB, 0))
	ack(p0, 0)
	require.Equal(t, int64(2), fetchCommittedOffset(t, client, group, topicA, 0))
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return tokens[p0][2] != "" }, 10*time.Second, 50*time.Millisecond, "acknowledging the contiguous prefix did not resume only the paused partition")
	ack(p0, 2)
	require.Equal(t, int64(3), fetchCommittedOffset(t, client, group, topicA, 0))
}

func fetchCommittedOffset(t *testing.T, client sarama.Client, group, topic string, partition int32) int64 {
	t.Helper()
	coordinator, err := client.Coordinator(group)
	require.NoError(t, err)
	request := &sarama.OffsetFetchRequest{ConsumerGroup: group, Version: 1}
	request.AddPartition(topic, partition)
	response, err := coordinator.FetchOffset(request)
	require.NoError(t, err)
	block := response.GetBlock(topic, partition)
	require.NotNil(t, block)
	return block.Offset
}

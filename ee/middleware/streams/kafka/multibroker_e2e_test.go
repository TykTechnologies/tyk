package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/warpstreamlabs/bento/public/service"
)

type kraftBrokerFixture struct {
	brokers    []string
	containers map[int32]testcontainers.Container
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startThreeBrokerKRaft(t *testing.T, ctx context.Context) *kraftBrokerFixture {
	t.Helper()
	brokerPorts, controllerPorts := make([]int, 3), make([]int, 3)
	for i := range 3 {
		brokerPorts[i], controllerPorts[i] = freeTCPPort(t), freeTCPPort(t)
	}
	voters := fmt.Sprintf("1@127.0.0.1:%d,2@127.0.0.1:%d,3@127.0.0.1:%d", controllerPorts[0], controllerPorts[1], controllerPorts[2])
	fixture := &kraftBrokerFixture{containers: map[int32]testcontainers.Container{}}
	for i := range 3 {
		nodeID := i + 1
		env := map[string]string{
			"CLUSTER_ID":    "MkU3OEVBNTcwNTJENDM2Qk",
			"KAFKA_NODE_ID": strconv.Itoa(nodeID), "KAFKA_PROCESS_ROLES": "broker,controller",
			"KAFKA_CONTROLLER_QUORUM_VOTERS":       voters,
			"KAFKA_LISTENERS":                      fmt.Sprintf("PLAINTEXT://0.0.0.0:%d,CONTROLLER://0.0.0.0:%d", brokerPorts[i], controllerPorts[i]),
			"KAFKA_ADVERTISED_LISTENERS":           fmt.Sprintf("PLAINTEXT://127.0.0.1:%d", brokerPorts[i]),
			"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
			"KAFKA_CONTROLLER_LISTENER_NAMES":      "CONTROLLER", "KAFKA_INTER_BROKER_LISTENER_NAME": "PLAINTEXT",
			"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "3", "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "3",
			"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "2", "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
		}
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
			Image: "confluentinc/confluent-local:7.5.0", Env: env,
			HostConfigModifier: func(h *dockercontainer.HostConfig) { h.NetworkMode = "host" },
		}, Started: false})
		require.NoError(t, err)
		fixture.containers[int32(nodeID)] = c
		fixture.brokers = append(fixture.brokers, fmt.Sprintf("127.0.0.1:%d", brokerPorts[i]))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for _, c := range fixture.containers {
		wg.Add(1)
		go func(c testcontainers.Container) { defer wg.Done(); errs <- c.Start(ctx) }(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		for _, c := range fixture.containers {
			_ = c.Terminate(context.Background())
		}
	})
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	require.Eventually(t, func() bool {
		client, err := sarama.NewClient(fixture.brokers, cfg)
		if err != nil {
			return false
		}
		client.Close()
		return true
	}, 45*time.Second, 250*time.Millisecond)
	return fixture
}

func TestExternalAcknowledgmentThreeBrokerLeaderFailoverE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cluster := startThreeBrokerKRaft(t, ctx)
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.Return.Successes = true
	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Partitioner = sarama.NewManualPartitioner
	cfg.Net.DialTimeout, cfg.Net.ReadTimeout, cfg.Net.WriteTimeout = 2*time.Second, 2*time.Second, 2*time.Second
	cfg.Metadata.Retry.Max = 3
	admin, err := sarama.NewClusterAdmin(cluster.brokers, cfg)
	require.NoError(t, err)
	defer admin.Close()
	topic, group, component := fmt.Sprintf("failover-%d", time.Now().UnixNano()), fmt.Sprintf("failover-group-%d", time.Now().UnixNano()), fmt.Sprintf("failover-component-%d", time.Now().UnixNano())
	minISR := "2"
	require.NoError(t, admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: 3, ReplicationFactor: 3, ConfigEntries: map[string]*string{"min.insync.replicas": &minISR}}, false))
	producer, err := sarama.NewSyncProducer(cluster.brokers, cfg)
	require.NoError(t, err)
	defer producer.Close()
	for partition := int32(0); partition < 3; partition++ {
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Partition: partition, Value: sarama.StringEncoder(fmt.Sprintf("before-failover-%d", partition))})
		require.NoError(t, err)
	}
	var mu sync.Mutex
	tokens := map[int32]string{}
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		partition, parseErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Partition"), 10, 32)
		if parseErr != nil {
			http.Error(w, "partition", http.StatusBadRequest)
			return
		}
		mu.Lock()
		tokens[int32(partition)] = r.Header.Get("Tyk-Kafka-Ack-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	provider, err := NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("three-broker-failover-signing-secret")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(component, provider))
	defer GlobalRuntimeAckKeyRegistry.Remove(component)
	builder := service.NewStreamBuilder()
	require.NoError(t, builder.SetYAML(fmt.Sprintf(`
input:
  tyk_kafka:
    seed_brokers: [%q,%q,%q]
    topics: [%q]
    consumer_group: %q
    acknowledgment:
      mode: external_ack
      component_id: %q
      checkpoint_limit: 1
      max_in_flight: 3
      max_in_flight_bytes: 1MiB
      routing: local
output:
  http_client:
    url: %q
    verb: POST
    headers:
      Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
      Tyk-Kafka-Partition: '${! @kafka_partition }'
`, cluster.brokers[0], cluster.brokers[1], cluster.brokers[2], topic, group, component, downstream.URL)))
	stream, err := builder.Build()
	require.NoError(t, err)
	go func() { _ = stream.Run(ctx) }()
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = stream.Stop(stopCtx)
	}()
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(tokens) == 3 }, 30*time.Second, 100*time.Millisecond)
	client, err := sarama.NewClient(cluster.brokers, cfg)
	require.NoError(t, err)
	coordinator, err := client.Coordinator(group)
	require.NoError(t, err)
	coordinatorID := coordinator.ID()
	var targetPartition int32 = -1
	var leaderID int32
	for partition := int32(0); partition < 3; partition++ {
		leader, leaderErr := client.Leader(topic, partition)
		require.NoError(t, leaderErr)
		if leader.ID() != coordinatorID {
			targetPartition, leaderID = partition, leader.ID()
			break
		}
	}
	require.NotEqual(t, int32(-1), targetPartition, "fixture must provide a partition leader distinct from the group coordinator")
	t.Logf("disruption target: partition=%d leader=%d initial_group_coordinator=%d", targetPartition, leaderID, coordinatorID)
	client.Close()
	key := ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: component}
	handler := NewAcknowledgmentHandler(GlobalControllerRegistry, key, HandlerLimits{})
	ack := func(token string) int {
		request := httptest.NewRequest(http.MethodPost, "/ack", bytes.NewBufferString(fmt.Sprintf(`{"tokens":[%q]}`, token)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	mu.Lock()
	snapshot := make(map[int32]string, len(tokens))
	for partition, token := range tokens {
		snapshot[partition] = token
	}
	mu.Unlock()
	for partition, token := range snapshot {
		if partition != targetPartition {
			require.Equal(t, http.StatusOK, ack(token))
		}
	}
	remaining := make([]string, 0, 2)
	for id, broker := range cluster.brokers {
		if int32(id+1) != leaderID {
			remaining = append(remaining, broker)
		}
	}
	require.NoError(t, cluster.containers[leaderID].Stop(ctx, nil))
	verify, err := sarama.NewClient(remaining, cfg)
	require.NoError(t, err)
	defer verify.Close()
	var electedLeaderID, healthyCoordinatorID int32
	require.Eventually(t, func() bool {
		if err := verify.RefreshMetadata(topic); err != nil {
			return false
		}
		leader, err := verify.Leader(topic, targetPartition)
		if err != nil || leader.ID() == leaderID {
			return false
		}
		if err := verify.RefreshCoordinator(group); err != nil {
			return false
		}
		coordinator, err := verify.Coordinator(group)
		if err != nil || coordinator.ID() == leaderID {
			return false
		}
		connected, err := coordinator.Connected()
		if err != nil || !connected {
			return false
		}
		electedLeaderID, healthyCoordinatorID = leader.ID(), coordinator.ID()
		return true
	}, 60*time.Second, 500*time.Millisecond, "survivors did not elect a leader and expose a reachable group coordinator")
	t.Logf("post-stop health: partition_leader=%d group_coordinator=%d", electedLeaderID, healthyCoordinatorID)
	require.Eventually(t, func() bool {
		mu.Lock()
		currentToken := tokens[targetPartition]
		mu.Unlock()
		return ack(currentToken) == http.StatusOK
	}, 30*time.Second, 250*time.Millisecond)
	require.Eventually(t, func() bool { return fetchCommittedOffset(t, verify, group, topic, targetPartition) == 1 }, 30*time.Second, 250*time.Millisecond)
}

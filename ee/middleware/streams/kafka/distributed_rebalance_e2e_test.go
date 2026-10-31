package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IBM/sarama"
	redis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

func TestDistributedAcknowledgmentTwoMemberOwnerTransferE2E(t *testing.T) {
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
	host, _ := redisContainer.Host(ctx)
	port, _ := redisContainer.MappedPort(ctx, "6379/tcp")
	redisClient := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	t.Cleanup(func() { _ = redisClient.Close() })
	transport, err := NewRedisDurableAckTransport(redisClient, RedisDurableAckOptions{Prefix: "e2e:rebalance"})
	require.NoError(t, err)
	topic := fmt.Sprintf("ack-owner-transfer-%d", time.Now().UnixNano())
	group := fmt.Sprintf("ack-owner-transfer-group-%d", time.Now().UnixNano())
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0
	saramaConfig.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = producer.Close() })
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("transfer-me")})
	require.NoError(t, err)
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "shared-input"}
	provider, err := NewSharedAckSigningKeyProvider("v1", map[string][]byte{"v1": []byte("two-member-e2e-shared-secret-value")})
	require.NoError(t, err)
	codec1, err := provider.ResolveAckTokenCodec(ctx, controllerScope(key))
	require.NoError(t, err)
	codec2, err := provider.ResolveAckTokenCodec(ctx, controllerScope(key))
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode = AcknowledgmentModeExternal
	config.CheckpointLimit = 4
	config.MaxInFlight = 4
	config.MaxInFlightBytes = 1 << 20
	c1, err := NewExternalAckController(key, brokers[0], "replay-one", codec1, config)
	require.NoError(t, err)
	c2, err := NewExternalAckController(key, brokers[0], "replay-two", codec2, config)
	require.NoError(t, err)
	o1, err := NewDistributedAckOwner(transport, key, "gateway-one", c1)
	require.NoError(t, err)
	defer o1.Close()
	o2, err := NewDistributedAckOwner(transport, key, "gateway-two", c2)
	require.NoError(t, err)
	defer o2.Close()

	newMember := func(controller *ExternalAckController, owner *DistributedAckOwner) (*kgo.Client, context.CancelFunc, <-chan *kgo.Record) {
		member, memberErr := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(topic), kgo.ConsumerGroup(group), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
			kgo.OnPartitionsAssigned(func(assignCtx context.Context, client *kgo.Client, partitions map[string][]int32) {
				controller.AssignPartitions(partitions)
				memberID, generation := client.GroupMetadata()
				require.NoError(t, owner.Assign(assignCtx, partitions, KafkaGroupIdentity{Generation: generation, MemberID: memberID}))
			}),
			kgo.OnPartitionsRevoked(func(_ context.Context, _ *kgo.Client, partitions map[string][]int32) {
				owner.Revoke(partitions)
				controller.LosePartitions(partitions)
			}))
		require.NoError(t, memberErr)
		controller.SetCommitter(member)
		pollCtx, pollCancel := context.WithCancel(ctx)
		records := make(chan *kgo.Record, 4)
		go func() {
			defer close(records)
			for pollCtx.Err() == nil {
				fetches := member.PollRecords(pollCtx, 1)
				iter := fetches.RecordIter()
				if !iter.Done() {
					records <- iter.Next()
				}
			}
		}()
		return member, pollCancel, records
	}
	member1, stopPoll1, records1 := newMember(c1, o1)
	var first *kgo.Record
	select {
	case first = <-records1:
	case <-time.After(20 * time.Second):
		t.Fatal("first member did not consume")
	}
	message1 := service.NewMessage(first.Value)
	require.NoError(t, c1.Track(first, message1))
	oldToken, _ := message1.MetaGet("tyk_kafka_ack_token")
	member2, stopPoll2, records2 := newMember(c2, o2)
	defer func() { stopPoll2(); member2.Close() }()
	adminClient, err := sarama.NewClient(brokers, saramaConfig)
	require.NoError(t, err)
	defer adminClient.Close()
	require.Eventually(t, func() bool {
		coordinator, e := adminClient.Coordinator(group)
		if e != nil {
			return false
		}
		response, e := coordinator.DescribeGroups(&sarama.DescribeGroupsRequest{Groups: []string{group}})
		return e == nil && len(response.Groups) == 1 && len(response.Groups[0].Members) == 2
	}, 20*time.Second, 100*time.Millisecond, "both Kafka members never joined")
	stopPoll1()
	member1.Close()
	c1.Close()
	var replay *kgo.Record
	select {
	case replay = <-records2:
	case <-time.After(20 * time.Second):
		t.Fatal("new owner did not receive safe redelivery")
	}
	require.Equal(t, int64(0), replay.Offset)
	message2 := service.NewMessage(replay.Value)
	require.NoError(t, c2.Track(replay, message2))
	newToken, _ := message2.MetaGet("tyk_kafka_ack_token")
	workerTokens := make(chan string, 1)
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerTokens <- r.Header.Get("Tyk-Kafka-Ack-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer worker.Close()
	request, _ := http.NewRequest(http.MethodPost, worker.URL, bytes.NewReader(replay.Value))
	request.Header.Set("Tyk-Kafka-Ack-Token", newToken)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, newToken, <-workerTokens)
	router, err := NewPartitionedDurableAcknowledgmentRouter(key, transport, codec2)
	require.NoError(t, err)

	post := func(token string) []AckResult {
		results, routeErr := router.Acknowledge(ctx, []string{token})
		require.NoError(t, routeErr)
		return results
	}
	require.Equal(t, AckQueued, post(oldToken)[0].Disposition)
	route := AckRoute{Key: key, Topic: topic, Partition: 0}
	require.Eventually(t, func() bool { return transport.Stats(ctx, route).Active == 0 }, 10*time.Second, 100*time.Millisecond, "new owner did not discard stale old-epoch command")
	require.Equal(t, int64(-1), fetchCommittedOffset(t, adminClient, group, topic, 0), "stale command must not commit across the crash")
	require.Equal(t, AckQueued, post(newToken)[0].Disposition)
	require.Eventually(t, func() bool { return fetchCommittedOffset(t, adminClient, group, topic, 0) == 1 }, 10*time.Second, 100*time.Millisecond, "new owner did not commit safely redelivered record")
}

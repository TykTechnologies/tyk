//go:build ee || dev

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestKafkaExternalAckTopologySoak is intentionally opt-in. Set
// TYK_KAFKA_SOAK_DURATION (for example 1m) and optionally
// TYK_KAFKA_SOAK_RESTART_INTERVAL (default 15s).
func TestKafkaExternalAckTopologySoak(t *testing.T) {
	durationText := os.Getenv("TYK_KAFKA_SOAK_DURATION")
	if durationText == "" {
		t.Skip("set TYK_KAFKA_SOAK_DURATION")
	}
	duration, err := time.ParseDuration(durationText)
	require.NoError(t, err)
	require.Positive(t, duration)
	restartEvery := 15 * time.Second
	if raw := os.Getenv("TYK_KAFKA_SOAK_RESTART_INTERVAL"); raw != "" {
		restartEvery, err = time.ParseDuration(raw)
		require.NoError(t, err)
		require.Positive(t, restartEvery)
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration+90*time.Second)
	defer cancel()
	kafkaContainer, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() {
		c, x := context.WithTimeout(context.Background(), 15*time.Second)
		defer x()
		_ = kafkaContainer.Terminate(c)
	})
	brokers, err := kafkaContainer.Brokers(ctx)
	require.NoError(t, err)
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		c, x := context.WithTimeout(context.Background(), 10*time.Second)
		defer x()
		_ = redisContainer.Terminate(c)
	})
	rh, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	rp, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	dockerClient, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dockerClient.Close() })
	executable, err := os.Executable()
	require.NoError(t, err)
	tmp := t.TempDir()
	worker, wr := startKafkaAcceptanceChild(t, executable, kafkaAcceptanceChildConfig{Role: "worker", ReadyFile: filepath.Join(tmp, "worker.json")})
	t.Cleanup(func() { stopKafkaAcceptanceChild(worker) })
	topic := fmt.Sprintf("soak-%d", time.Now().UnixNano())
	group := topic + "-group"
	listen := "/soak/"
	base := kafkaAcceptanceChildConfig{Role: "gateway", Broker: brokers[0], Topic: topic, Group: group, WorkerURL: wr.URL + "/deliver", RedisHost: rh, RedisPort: rp.Int(), RedisDB: 11, APIID: "kafka-soak", ListenPath: listen, Secret: "soak-secret-must-be-at-least-32-bytes"}
	configs := []kafkaAcceptanceChildConfig{base, base}
	configs[0].ReadyFile = filepath.Join(tmp, "g0.json")
	configs[1].ReadyFile = filepath.Join(tmp, "g1.json")
	cmds := make([]*exec.Cmd, 2)
	ready := make([]kafkaAcceptanceChildReady, 2)
	for i := range cmds {
		cmds[i], ready[i] = startKafkaAcceptanceChild(t, executable, configs[i])
	}
	t.Cleanup(func() {
		for _, cmd := range cmds {
			stopKafkaAcceptanceChild(cmd)
		}
	})
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	configureKafkaSoakProducer(cfg)
	require.NoError(t, cfg.Validate())
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	defer producer.Close()
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	defer client.Close()
	deadline := time.Now().Add(duration)
	nextRestart := time.Now().Add(restartEvery)
	produced, lastCommitted, expectedCommitted := int64(0), int64(-1), int64(-1)
	deliveryTimeout := 60 * time.Second
	if raw := os.Getenv("TYK_KAFKA_SOAK_DELIVERY_TIMEOUT"); raw != "" {
		deliveryTimeout, err = time.ParseDuration(raw)
		require.NoError(t, err)
		require.Positive(t, deliveryTimeout)
	}
	started := time.Now()
	redisDisrupted, kafkaDisrupted := false, false
	for time.Now().Before(deadline) {
		elapsed := time.Since(started)
		if !redisDisrupted && elapsed >= duration/3 {
			t.Log("pausing Redis")
			require.NoError(t, dockerClient.ContainerPause(ctx, redisContainer.GetContainerID()))
			time.Sleep(time.Second)
			require.NoError(t, dockerClient.ContainerUnpause(ctx, redisContainer.GetContainerID()))
			redisDisrupted = true
		}
		if !kafkaDisrupted && elapsed >= 2*duration/3 {
			t.Log("pausing Kafka broker")
			require.NoError(t, dockerClient.ContainerPause(ctx, kafkaContainer.GetContainerID()))
			time.Sleep(time.Second)
			require.NoError(t, dockerClient.ContainerUnpause(ctx, kafkaContainer.GetContainerID()))
			kafkaDisrupted = true
		}
		eventBody := fmt.Sprintf("event-%d", produced)
		partition, offset, sendErr := producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder(eventBody)})
		err = sendErr
		require.NoError(t, err)
		produced++
		expectedCommitted = offset + 1
		delivery := waitKafkaSoakDelivery(t, wr.URL, topic, partition, offset, eventBody, "", "", ready, configs, cmds, listen, client, group, deliveryTimeout)
		if !time.Now().Before(nextRestart) {
			owner, _ := identifyKafkaAcceptanceOwner(t, ready, listen)
			idx := 0
			if owner.URL == ready[1].URL {
				idx = 1
			}
			require.NoError(t, cmds[idx].Process.Kill())
			_ = cmds[idx].Wait()
			if logFile, ok := cmds[idx].Stdout.(*os.File); ok {
				require.NoError(t, logFile.Close())
			}
			require.NoError(t, os.Remove(configs[idx].ReadyFile))
			cmds[idx], ready[idx] = startKafkaAcceptanceChild(t, executable, configs[idx])
			delivery = waitKafkaSoakDelivery(t, wr.URL, topic, partition, offset, eventBody, delivery.Token, delivery.DeliveryID, ready, configs, cmds, listen, client, group, deliveryTimeout)
			nextRestart = time.Now().Add(restartEvery)
		}
		ingress := ready[produced%2]
		response, body := kafkaGatewayPost(t, ingress.URL+listen+"worker/kafka/ack", ingress.Key, fmt.Sprintf(`{"tokens":[%q]}`, delivery.Token))
		require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
		var current int64
		require.Eventually(t, func() bool {
			var ok bool
			current, ok = tryKafkaSoakCommittedOffset(client, group, topic, 0)
			return ok && current >= expectedCommitted
		}, 20*time.Second, 100*time.Millisecond)
		require.GreaterOrEqual(t, current, lastCommitted)
		require.LessOrEqual(t, current, expectedCommitted)
		lastCommitted = current
	}
	require.Equal(t, expectedCommitted, gatewayFetchCommittedOffset(t, client, group, topic, 0))
	require.True(t, redisDisrupted, "soak ended before Redis disruption")
	require.True(t, kafkaDisrupted, "soak ended before Kafka disruption")
}

// configureKafkaSoakProducer prevents an acknowledged append whose response is
// lost during the broker-pause phase from being appended a second time on
// retry. Without idempotence SendMessage can return the later duplicate offset
// while checkpoint_limit=1 correctly pauses on the first copy, causing the
// harness itself to wait past an unacknowledged lower offset.
func configureKafkaSoakProducer(cfg *sarama.Config) {
	cfg.Producer.Return.Successes = true
	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Idempotent = true
	cfg.Net.MaxOpenRequests = 1
}

func TestConfigureKafkaSoakProducerIsIdempotent(t *testing.T) {
	cfg := sarama.NewConfig()
	configureKafkaSoakProducer(cfg)
	require.True(t, cfg.Producer.Return.Successes)
	require.Equal(t, sarama.WaitForAll, cfg.Producer.RequiredAcks)
	require.True(t, cfg.Producer.Idempotent)
	require.Equal(t, 1, cfg.Net.MaxOpenRequests)
	require.NoError(t, cfg.Validate())
}

func tryKafkaSoakCommittedOffset(client sarama.Client, group, topic string, partition int32) (int64, bool) {
	coordinator, err := client.Coordinator(group)
	if err != nil {
		return 0, false
	}
	request := &sarama.OffsetFetchRequest{ConsumerGroup: group, Version: 1}
	request.AddPartition(topic, partition)
	response, err := coordinator.FetchOffset(request)
	if err != nil {
		return 0, false
	}
	block := response.GetBlock(topic, partition)
	if block == nil || block.Err != sarama.ErrNoError {
		return 0, false
	}
	return block.Offset, true
}

func waitKafkaSoakDelivery(t *testing.T, workerURL, topic string, partition int32, offset int64, body, excludeToken, excludeDeliveryID string, gateways []kafkaAcceptanceChildReady, configs []kafkaAcceptanceChildConfig, cmds []*exec.Cmd, listenPath string, client sarama.Client, group string, timeout time.Duration) gatewayKafkaDelivery {
	t.Helper()
	var deliveries []gatewayKafkaDelivery
	var matched gatewayKafkaDelivery
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		response, err := http.Get(workerURL + "/deliveries?tail=256")
		if err == nil {
			decodeErr := json.NewDecoder(response.Body).Decode(&deliveries)
			response.Body.Close()
			if decodeErr == nil {
				if candidate, ok := selectKafkaSoakDelivery(deliveries, topic, partition, offset, body, excludeToken, excludeDeliveryID); ok {
					matched = candidate
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if matched.Token != "" {
		return matched
	}
	for i, gateway := range gateways {
		response, status := kafkaGatewayGet(t, gateway.URL+listenPath+"worker/kafka/status", gateway.Key)
		logBody, _ := os.ReadFile(configs[i].ReadyFile + ".log")
		pid, processState := 0, "missing"
		if i < len(cmds) && cmds[i] != nil && cmds[i].Process != nil {
			pid = cmds[i].Process.Pid
			processState = "running"
			if cmds[i].ProcessState != nil {
				processState = cmds[i].ProcessState.String()
			}
		}
		t.Logf("gateway[%d] pid=%d process=%s status=%d body=%s\nlog:\n%s", i, pid, processState, response.StatusCode, status, logBody)
	}
	newest, newestErr := client.GetOffset(topic, 0, sarama.OffsetNewest)
	committed, committedOK := tryKafkaSoakCommittedOffset(client, group, topic, 0)
	admin, adminErr := sarama.NewClusterAdminFromClient(client)
	if adminErr == nil {
		descriptions, describeErr := admin.DescribeConsumerGroups([]string{group})
		t.Logf("Kafka group descriptions=%+v describe_error=%v", descriptions, describeErr)
		_ = admin.Close()
	} else {
		t.Logf("Kafka group admin error=%v", adminErr)
	}
	var last any = "none"
	if len(deliveries) > 0 {
		last = deliveries[len(deliveries)-1]
	}
	t.Logf("Kafka newest=%d newest_error=%v committed=%d committed_ok=%v last_delivery=%+v", newest, newestErr, committed, committedOK, last)
	t.Fatalf("wanted delivery topic=%s partition=%d offset=%d body=%q excluding_token=%t; observed %d", topic, partition, offset, body, excludeToken != "", len(deliveries))
	return gatewayKafkaDelivery{}
}

func selectKafkaSoakDelivery(deliveries []gatewayKafkaDelivery, topic string, partition int32, offset int64, body, excludeToken, excludeDeliveryID string) (gatewayKafkaDelivery, bool) {
	wantPartition, wantOffset := strconv.FormatInt(int64(partition), 10), strconv.FormatInt(offset, 10)
	for _, delivery := range deliveries {
		if delivery.Topic == topic && delivery.Partition == wantPartition && delivery.Offset == wantOffset && delivery.Body == body && delivery.Token != "" && (excludeToken == "" || delivery.Token != excludeToken) && (excludeDeliveryID == "" || delivery.DeliveryID != excludeDeliveryID) {
			return delivery, true
		}
	}
	return gatewayKafkaDelivery{}, false
}

func TestSelectKafkaSoakDeliveryIgnoresReplayCountSkew(t *testing.T) {
	deliveries := []gatewayKafkaDelivery{
		{Topic: "employees", Partition: "0", Offset: "0", Body: "event-0", Token: "t0", DeliveryID: "d0"},
		{Topic: "employees", Partition: "0", Offset: "1", Body: "event-1", Token: "t1", DeliveryID: "d1"},
		{Topic: "employees", Partition: "0", Offset: "1", Body: "event-1", Token: "t1-replay", DeliveryID: "d1-replay"},
		{Topic: "employees", Partition: "0", Offset: "2", Body: "event-2", Token: "t2", DeliveryID: "d2"},
	}
	matched, ok := selectKafkaSoakDelivery(deliveries, "employees", 0, 2, "event-2", "", "")
	require.True(t, ok)
	require.Equal(t, "t2", matched.Token, "the third delivery is a duplicate and must not satisfy offset 2")
	replay, ok := selectKafkaSoakDelivery(deliveries, "employees", 0, 1, "event-1", "t1", "")
	require.True(t, ok)
	require.Equal(t, "t1-replay", replay.Token)
}

func TestAppendBoundedKafkaDeliveriesRetainsNewest(t *testing.T) {
	deliveries := make([]gatewayKafkaDelivery, 0, maxKafkaAcceptanceDeliveries)
	for i := 0; i < maxKafkaAcceptanceDeliveries+3; i++ {
		deliveries = appendBoundedKafkaDeliveries(deliveries, gatewayKafkaDelivery{Offset: strconv.Itoa(i)})
	}
	require.Len(t, deliveries, maxKafkaAcceptanceDeliveries)
	require.Equal(t, "3", deliveries[0].Offset)
	require.Equal(t, strconv.Itoa(maxKafkaAcceptanceDeliveries+2), deliveries[len(deliveries)-1].Offset)
}

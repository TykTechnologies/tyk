//go:build ee || dev

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	streamkafka "github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
	"github.com/TykTechnologies/tyk/user"
)

// TestKafkaManualCommitPoC_GatewayE2E exercises PR #8177 through the actual
// Gateway request path, rather than calling its stream and handler directly.
func TestKafkaExternalAcknowledgmentGatewayE2E(t *testing.T) {
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

	topic := fmt.Sprintf("gateway-manual-commit-%d", time.Now().UnixNano())
	group := fmt.Sprintf("gateway-manual-group-%d", time.Now().UnixNano())
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0
	saramaConfig.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("gateway-event")})
	require.NoError(t, err)

	var deliveries atomic.Int32
	var ackToken atomic.Value
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		ackToken.Store(r.Header.Get("Tyk-Kafka-Ack-Token"))
		deliveries.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)

	ts := StartTest(func(globalConf *config.Config) { globalConf.Streaming.Enabled = true })
	t.Cleanup(ts.Close)
	const apiID = "kafka-ack-e2e"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/manual-kafka/"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
		spec.IsOAS = true
		spec.OAS = kafkaManualCommitOAS(t, brokers[0], topic, group, downstream.URL)
		spec.OAS.Fill(*spec.APIDefinition)
	})
	ackKey := kafkaGatewaySession(ts, apiID, []string{"kafka:ack"})
	statusKey := kafkaGatewaySession(ts, apiID, []string{"kafka:status"})
	missingPermissionKey := kafkaGatewaySession(ts, apiID, nil)
	wrongPermissionKey := kafkaGatewaySession(ts, apiID, []string{"kafka:offset-reset"})

	require.Eventually(t, func() bool {
		token, _ := ackToken.Load().(string)
		return deliveries.Load() == 1 && token != ""
	}, 30*time.Second, 100*time.Millisecond)

	client, err := sarama.NewClient(brokers, saramaConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.Equal(t, int64(-1), gatewayFetchCommittedOffset(t, client, group, topic, 0))
	statusResponse, statusBody := kafkaGatewayGet(t, ts.URL+"/manual-kafka/worker/kafka/status?partition_limit=1", statusKey)
	require.Equal(t, http.StatusOK, statusResponse.StatusCode, string(statusBody))
	require.Contains(t, string(statusBody), `"in_flight":1`)
	statusResponse, statusBody = kafkaGatewayGet(t, ts.URL+"/manual-kafka/worker/kafka/status", ackKey)
	require.Equal(t, http.StatusForbidden, statusResponse.StatusCode, string(statusBody))

	ackPayload := fmt.Sprintf(`{"tokens":[%q]}`, ackToken.Load().(string))
	for _, key := range []string{missingPermissionKey, wrongPermissionKey} {
		response, body := kafkaGatewayPost(t, ts.URL+"/manual-kafka/worker/kafka/ack", key, ackPayload)
		require.Equal(t, http.StatusForbidden, response.StatusCode, string(body))
	}
	forgedPayload := fmt.Sprintf(`{"tokens":[%q]}`, ackToken.Load().(string)+"forged")
	response, body := kafkaGatewayPost(t, ts.URL+"/manual-kafka/worker/kafka/ack", ackKey, forgedPayload)
	require.Equal(t, http.StatusBadRequest, response.StatusCode, string(body))
	require.Equal(t, int64(-1), gatewayFetchCommittedOffset(t, client, group, topic, 0), "forged token advanced Kafka")

	parts := strings.Split(ackToken.Load().(string), ".")
	require.Len(t, parts, 4)
	claimsPayload, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	var expiredClaims streamkafka.AckClaims
	require.NoError(t, json.Unmarshal(claimsPayload, &expiredClaims))
	expiredClaims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expiredClaims.IssuedAt = expiredClaims.ExpiresAt - 1
	codec, err := streamkafka.GlobalRuntimeAckKeyRegistry.Resolve(ctx, apiID+"_worker_gateway", expiredClaims.Scope)
	require.NoError(t, err)
	expiredToken, err := codec.Sign(expiredClaims)
	require.NoError(t, err)
	response, body = kafkaGatewayPost(t, ts.URL+"/manual-kafka/worker/kafka/ack", ackKey, fmt.Sprintf(`{"tokens":[%q]}`, expiredToken))
	require.Equal(t, http.StatusGone, response.StatusCode, string(body))
	require.Equal(t, int64(-1), gatewayFetchCommittedOffset(t, client, group, topic, 0), "expired token advanced Kafka")

	response, body = kafkaGatewayPost(t, ts.URL+"/manual-kafka/worker/kafka/ack", ackKey, ackPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	require.Eventually(t, func() bool {
		return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1
	}, 10*time.Second, 100*time.Millisecond)
	require.Equal(t, int32(1), deliveries.Load())
}

func TestKafkaControlRoutesForbiddenForKeylessAPI(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) { globalConf.Streaming.Enabled = true })
	t.Cleanup(ts.Close)
	const apiID = "keyless-kafka-controls"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/keyless-kafka/"
		spec.UseKeylessAccess = true
		spec.UseStandardAuth = false
		spec.IsOAS = true
		spec.OAS = kafkaManualCommitOAS(t, "127.0.0.1:1", "never-connect", "keyless-control-group", "http://127.0.0.1:1")
		spec.OAS.Fill(*spec.APIDefinition)
	})
	response, body := kafkaGatewayPost(t, ts.URL+"/keyless-kafka/worker/kafka/ack", "", `{"tokens":["forged"]}`)
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, response.StatusCode, string(body))
	response, body = kafkaGatewayGet(t, ts.URL+"/keyless-kafka/worker/kafka/status", "")
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, response.StatusCode, string(body))
}

// TestKafkaMissingAcknowledgmentGatewayE2E covers deadline behavior through a
// real broker and the Gateway stream route. Assertions poll observable Kafka
// state and downstream deliveries; no correctness assertion relies on sleep.
func TestKafkaMissingAcknowledgmentGatewayE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	cfg.Producer.Partitioner = sarama.NewManualPartitioner

	t.Run("redelivery_is_partition_scoped", func(t *testing.T) {
		topic, group := fmt.Sprintf("deadline-redeliver-%d", time.Now().UnixNano()), fmt.Sprintf("deadline-group-%d", time.Now().UnixNano())
		admin, err := sarama.NewClusterAdmin(brokers, cfg)
		require.NoError(t, err)
		require.NoError(t, admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: 2, ReplicationFactor: 1}, false))
		require.NoError(t, admin.Close())
		producer, err := sarama.NewSyncProducer(brokers, cfg)
		require.NoError(t, err)
		defer producer.Close()
		for _, m := range []*sarama.ProducerMessage{{Topic: topic, Partition: 0, Value: sarama.StringEncoder("blocked")}, {Topic: topic, Partition: 1, Value: sarama.StringEncoder("free-1")}, {Topic: topic, Partition: 1, Value: sarama.StringEncoder("free-2")}} {
			_, _, err = producer.SendMessage(m)
			require.NoError(t, err)
		}

		var mu sync.Mutex
		var got []gatewayKafkaDelivery
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			mu.Lock()
			got = append(got, gatewayKafkaDelivery{Token: r.Header.Get("Tyk-Kafka-Ack-Token"), Partition: r.Header.Get("Tyk-Kafka-Partition"), Body: string(b)})
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer downstream.Close()
		ts, key := startKafkaDeadlineGateway(t, brokers[0], topic, group, downstream.URL, "redeliver", "", "redelivery_max_attempts: 3\n          redelivery_backoff: 100ms\n          redelivery_max_backoff: 200ms")
		defer ts.Close()
		require.Eventually(t, func() bool {
			mu.Lock()
			snapshot := append([]gatewayKafkaDelivery(nil), got...)
			mu.Unlock()
			seenFree2, blockedCount := false, 0
			for _, d := range snapshot {
				if d.Body == "blocked" {
					blockedCount++
				}
				if d.Body == "free-2" {
					seenFree2 = true
				}
				if d.Partition == "1" {
					resp, _ := kafkaGatewayPost(t, ts.URL+"/deadline-kafka/worker/kafka/ack", key, fmt.Sprintf(`{"tokens":[%q]}`, d.Token))
					if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
						return false
					}
				}
			}
			return seenFree2 && blockedCount >= 2
		}, 30*time.Second, 100*time.Millisecond, "partition 1 must continue while only partition 0 is replayed")
	})

	t.Run("pause_recovers_with_late_valid_ack", func(t *testing.T) {
		topic, group := fmt.Sprintf("deadline-pause-%d", time.Now().UnixNano()), fmt.Sprintf("deadline-pause-group-%d", time.Now().UnixNano())
		admin, err := sarama.NewClusterAdmin(brokers, cfg)
		require.NoError(t, err)
		require.NoError(t, admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
		require.NoError(t, admin.Close())
		producer, err := sarama.NewSyncProducer(brokers, cfg)
		require.NoError(t, err)
		defer producer.Close()
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("first")})
		require.NoError(t, err)
		var mu sync.Mutex
		var got []gatewayKafkaDelivery
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			mu.Lock()
			got = append(got, gatewayKafkaDelivery{Token: r.Header.Get("Tyk-Kafka-Ack-Token"), Body: string(b)})
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer downstream.Close()
		ts, key := startKafkaDeadlineGateway(t, brokers[0], topic, group, downstream.URL, "pause", "", "")
		defer ts.Close()
		require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 }, 20*time.Second, 100*time.Millisecond)
		require.Eventually(t, func() bool {
			resp, body := kafkaGatewayGet(t, ts.URL+"/deadline-kafka/worker/kafka/status", key)
			return resp.StatusCode == http.StatusOK && strings.Contains(string(body), `"paused":true`)
		}, 10*time.Second, 100*time.Millisecond)
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("second")})
		require.NoError(t, err)
		// Past the deadline, the partition is terminally paused and the second record is not delivered.
		require.Never(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) > 1 }, 1200*time.Millisecond, 50*time.Millisecond)
		mu.Lock()
		token := got[0].Token
		mu.Unlock()
		resp, body := kafkaGatewayPost(t, ts.URL+"/deadline-kafka/worker/kafka/ack", key, fmt.Sprintf(`{"tokens":[%q]}`, token))
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 && got[1].Body == "second" }, 20*time.Second, 100*time.Millisecond)
	})

	t.Run("dead_letter_durability_gates_source_commit", func(t *testing.T) {
		for _, tc := range []struct {
			name, dlq  string
			wantCommit bool
		}{{"success", fmt.Sprintf("dlq-%d", time.Now().UnixNano()), true}, {"produce_failure", "invalid topic name", false}} {
			t.Run(tc.name, func(t *testing.T) {
				topic, group := fmt.Sprintf("deadline-dlq-%d", time.Now().UnixNano()), fmt.Sprintf("deadline-dlq-group-%d", time.Now().UnixNano())
				admin, err := sarama.NewClusterAdmin(brokers, cfg)
				require.NoError(t, err)
				require.NoError(t, admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
				require.NoError(t, admin.Close())
				producer, err := sarama.NewSyncProducer(brokers, cfg)
				require.NoError(t, err)
				defer producer.Close()
				_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("expire")})
				require.NoError(t, err)
				downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					r.Body.Close()
					w.WriteHeader(http.StatusOK)
				}))
				defer downstream.Close()
				ts, _ := startKafkaDeadlineGateway(t, brokers[0], topic, group, downstream.URL, "dead_letter", tc.dlq, "")
				defer ts.Close()
				client, err := sarama.NewClient(brokers, cfg)
				require.NoError(t, err)
				defer client.Close()
				if tc.wantCommit {
					require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1 }, 20*time.Second, 100*time.Millisecond)
					consumer, err := sarama.NewConsumer(brokers, cfg)
					require.NoError(t, err)
					defer consumer.Close()
					partition, err := consumer.ConsumePartition(tc.dlq, 0, sarama.OffsetOldest)
					require.NoError(t, err)
					defer partition.Close()
					select {
					case message := <-partition.Messages():
						require.Equal(t, "expire", string(message.Value))
					case <-time.After(10 * time.Second):
						t.Fatal("source committed without an observable durable DLQ record")
					}
				} else {
					require.Never(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) > 0 }, 2*time.Second, 100*time.Millisecond)
				}
			})
		}
	})

	t.Run("retention_truncation_with_open_window_recovers", func(t *testing.T) {
		topic, group := fmt.Sprintf("deadline-retention-%d", time.Now().UnixNano()), fmt.Sprintf("deadline-retention-group-%d", time.Now().UnixNano())
		admin, err := sarama.NewClusterAdmin(brokers, cfg)
		require.NoError(t, err)
		require.NoError(t, admin.CreateTopic(topic, &sarama.TopicDetail{NumPartitions: 1, ReplicationFactor: 1}, false))
		defer admin.Close()
		producer, err := sarama.NewSyncProducer(brokers, cfg)
		require.NoError(t, err)
		defer producer.Close()
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Partition: 0, Value: sarama.StringEncoder("will-expire")})
		require.NoError(t, err)
		var mu sync.Mutex
		var bodies []string
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			mu.Lock()
			bodies = append(bodies, string(body))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer downstream.Close()
		ts, key := startKafkaDeadlineGateway(t, brokers[0], topic, group, downstream.URL, "redeliver", "", "redelivery_max_attempts: 8\n          redelivery_backoff: 100ms\n          redelivery_max_backoff: 200ms")
		defer ts.Close()
		require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(bodies) >= 1 }, 20*time.Second, 100*time.Millisecond)
		inFlight := func() int {
			resp, body := kafkaGatewayGet(t, ts.URL+"/deadline-kafka/worker/kafka/status", key)
			if resp.StatusCode != http.StatusOK {
				return -1
			}
			var status streamkafka.ExternalAckStatus
			if json.Unmarshal(body, &status) != nil {
				return -1
			}
			return status.InFlight
		}
		require.Equal(t, 1, inFlight())
		require.NoError(t, admin.DeleteRecords(topic, map[int32]int64{0: 1}))
		require.Eventually(t, func() bool { return inFlight() == 0 }, 10*time.Second, 100*time.Millisecond, "deadline did not fence the truncated open window")
		_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Partition: 0, Value: sarama.StringEncoder("after-truncation")})
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			for _, body := range bodies {
				if body == "after-truncation" {
					return true
				}
			}
			return false
		}, 30*time.Second, 100*time.Millisecond, "OffsetOutOfRange recovery deadlocked the partition after retention advanced log start")
	})
}

type gatewayKafkaDelivery struct{ Token, DeliveryID, ReplayID, Topic, Partition, Offset, Body string }

func TestKafkaOffsetResetGatewayE2E(t *testing.T) {
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
	topic := fmt.Sprintf("gateway-reset-%d", time.Now().UnixNano())
	group := fmt.Sprintf("gateway-reset-group-%d", time.Now().UnixNano())
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, producer.Close()) })
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("reset-and-replay")})
	require.NoError(t, err)
	var mu sync.Mutex
	var deliveries []gatewayKafkaDelivery
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		deliveries = append(deliveries, gatewayKafkaDelivery{Token: r.Header.Get("Tyk-Kafka-Ack-Token"), DeliveryID: r.Header.Get("Tyk-Kafka-Delivery-ID"), ReplayID: r.Header.Get("Tyk-Kafka-Replay-ID"), Partition: r.Header.Get("Tyk-Kafka-Partition"), Body: string(body)})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(downstream.Close)
	ts := StartTest(func(globalConf *config.Config) { globalConf.Streaming.Enabled = true })
	t.Cleanup(ts.Close)
	const apiID = "kafka-reset-e2e"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/reset-kafka/"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
		spec.IsOAS = true
		spec.OAS = kafkaManualCommitOAS(t, brokers[0], topic, group, downstream.URL)
		spec.OAS.Fill(*spec.APIDefinition)
	})
	fullKey := kafkaGatewaySession(ts, apiID, []string{"kafka:ack"})
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(deliveries) == 1 && deliveries[0].Token != "" }, 30*time.Second, 100*time.Millisecond)
	mu.Lock()
	first := deliveries[0]
	mu.Unlock()
	require.Equal(t, "reset-and-replay", first.Body)
	post := func(key, path, payload string) (*http.Response, []byte) {
		return kafkaGatewayPost(t, ts.URL+path, key, payload)
	}
	response, body := post(fullKey, "/reset-kafka/worker/kafka/ack", fmt.Sprintf(`{"tokens":[%q]}`, first.Token))
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1 }, 10*time.Second, 100*time.Millisecond)
	planPayload := fmt.Sprintf(`{"consumer_group":%q,"reason":"gateway e2e replay","targets":[{"topic":%q,"partition":0,"offset":0}]}`, group, topic)
	oldResponse, oldBody := post(fullKey, "/reset-kafka/worker/kafka/offset/reset/plan", planPayload)
	require.Contains(t, []int{http.StatusNotFound, http.StatusForbidden}, oldResponse.StatusCode, string(oldBody))
	controlPath := fmt.Sprintf("/tyk/streams/%s/worker/kafka/%s_worker_gateway/offset/reset", apiID, apiID)
	for _, secret := range []string{"", "wrong-admin-secret"} {
		response, body = kafkaGatewayControlPost(t, ts.URL+controlPath+"/plan", secret, planPayload)
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, response.StatusCode, string(body))
	}
	response, body = kafkaGatewayControlPost(t, ts.URL+controlPath+"/plan", ts.Gw.GetConfig().Secret, planPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	var plan streamkafka.ResetPlan
	require.NoError(t, json.Unmarshal(body, &plan))
	require.NotEmpty(t, plan.ID)
	response, body = kafkaGatewayControlPost(t, ts.URL+controlPath+"/execute", ts.Gw.GetConfig().Secret, fmt.Sprintf(`{"plan_id":%q}`, plan.ID))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(deliveries) >= 2 }, 30*time.Second, 100*time.Millisecond)
	mu.Lock()
	replay := deliveries[1]
	mu.Unlock()
	require.Equal(t, "reset-and-replay", replay.Body)
	require.NotEmpty(t, replay.Token)
	require.NotEqual(t, first.Token, replay.Token)
	require.NotEmpty(t, replay.DeliveryID)
	require.NotEqual(t, first.DeliveryID, replay.DeliveryID)
	require.NotEmpty(t, replay.ReplayID)
	require.NotEqual(t, first.ReplayID, replay.ReplayID)
	response, body = post(fullKey, "/reset-kafka/worker/kafka/ack", fmt.Sprintf(`{"tokens":[%q]}`, first.Token))
	require.Equal(t, http.StatusConflict, response.StatusCode, string(body))
}

func kafkaGatewaySession(ts *Test, apiID string, permissions []string) string {
	return CreateSession(ts.Gw, func(session *user.SessionState) {
		session.AccessRights = map[string]user.AccessDefinition{apiID: {APIID: apiID, Versions: []string{"Default"}}}
		session.MetaData["kafka_permissions"] = permissions
	})
}

func kafkaGatewayPost(t *testing.T, endpoint, key, payload string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(payload))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", key)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	return response, body
}

func kafkaGatewayControlPost(t *testing.T, endpoint, secret, payload string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(payload))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	if secret != "" {
		request.Header.Set("x-tyk-authorization", secret)
	}
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	return response, body
}

func kafkaGatewayGet(t *testing.T, endpoint, key string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", key)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	return response, body
}

func kafkaManualCommitOAS(t *testing.T, broker, topic, group, downstream string) oas.OAS {
	t.Helper()
	streamConfig := fmt.Sprintf(`
streams:
  worker:
    input:
      tyk_kafka:
        seed_brokers: [%q]
        topics: [%q]
        consumer_group: %q
        acknowledgment:
          mode: external_ack
          component_id: gateway
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
          Tyk-Kafka-Delivery-ID: '${! @tyk_kafka_delivery_id }'
          Tyk-Kafka-Replay-ID: '${! @tyk_kafka_replay_generation }'
          Tyk-Kafka-Partition: '${! @kafka_partition }'
          Tyk-Kafka-Topic: '${! @kafka_topic }'
          Tyk-Kafka-Offset: '${! @kafka_offset }'
`, broker, topic, group, downstream)
	payload, err := ConvertYAMLToJSON([]byte(streamConfig))
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &parsed))
	result := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "Kafka manual commit e2e", Version: "1"},
			Paths:   openapi3.NewPaths(),
		},
	}
	result.Extensions = map[string]interface{}{streams.ExtensionTykStreaming: parsed}
	return result
}

func startKafkaDeadlineGateway(t *testing.T, broker, topic, group, downstream, policy, dlq, extra string) (*Test, string) {
	t.Helper()
	checkpointLimit := 8
	if policy == "pause" {
		checkpointLimit = 1
	}
	ts := StartTest(func(globalConf *config.Config) { globalConf.Streaming.Enabled = true })
	const apiID = "kafka-deadline-e2e"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/deadline-kafka/"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
		spec.IsOAS = true
		streamConfig := fmt.Sprintf(`
streams:
  worker:
    input:
      tyk_kafka:
        seed_brokers: [%q]
        topics: [%q]
        consumer_group: %q
        start_from_oldest: true
        acknowledgment:
          mode: external_ack
          component_id: %q
          checkpoint_limit: %d
          max_in_flight: 32
          max_in_flight_bytes: 1MiB
          ack_deadline: 500ms
          token_ttl: 30s
          commit_interval: 20ms
          routing: local
          missing_ack_policy: %s
          dead_letter_topic: %q
          %s
    output:
      http_client:
        url: %q
        verb: POST
        headers:
          Tyk-Kafka-Ack-Token: '${! @tyk_kafka_ack_token }'
          Tyk-Kafka-Partition: '${! @kafka_partition }'
`, broker, topic, group, topic, checkpointLimit, policy, dlq, extra, downstream)
		payload, err := ConvertYAMLToJSON([]byte(streamConfig))
		require.NoError(t, err)
		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(payload, &parsed))
		spec.OAS = oas.OAS{T: openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "Kafka deadline e2e", Version: "1"}, Paths: openapi3.NewPaths()}}
		spec.OAS.Extensions = map[string]interface{}{streams.ExtensionTykStreaming: parsed}
		spec.OAS.Fill(*spec.APIDefinition)
	})
	key := kafkaGatewaySession(ts, apiID, []string{"kafka:ack", "kafka:status"})
	require.Eventually(t, func() bool {
		resp, _ := kafkaGatewayGet(t, ts.URL+"/deadline-kafka/worker/kafka/status", key)
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "deadline stream did not register")
	return ts, key
}

func gatewayFetchCommittedOffset(t *testing.T, client sarama.Client, group, topic string, partition int32) int64 {
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

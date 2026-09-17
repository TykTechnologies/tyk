//go:build ee || dev

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	streamkafka "github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/testcontainers/testcontainers-go/wait"
)

// kafkaAcceptanceChildConfig is intentionally JSON/env based so a parent test
// can launch the already-built gateway test binary without building another
// executable. Each child is a real OS process with an independent Gateway and
// controller registry.
type kafkaAcceptanceChildConfig struct {
	Role       string `json:"role"`
	ReadyFile  string `json:"ready_file"`
	Broker     string `json:"broker"`
	Topic      string `json:"topic"`
	Group      string `json:"group"`
	WorkerURL  string `json:"worker_url"`
	RedisHost  string `json:"redis_host"`
	RedisPort  int    `json:"redis_port"`
	RedisDB    int    `json:"redis_db"`
	APIID      string `json:"api_id"`
	ListenPath string `json:"listen_path"`
	Secret     string `json:"secret"`
}

type kafkaAcceptanceChildReady struct {
	URL string `json:"url"`
	Key string `json:"key,omitempty"`
}

func TestKafkaExternalAckTwoGatewaySubprocessE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker and subprocesses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	kafkaContainer, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = kafkaContainer.Terminate(context.Background()) })
	brokers, err := kafkaContainer.Brokers(ctx)
	require.NoError(t, err)
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisContainer.Terminate(context.Background()) })
	redisHost, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	redisPort, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	executable, err := os.Executable()
	require.NoError(t, err)
	tmp := t.TempDir()
	worker, workerReady := startKafkaAcceptanceChild(t, executable, kafkaAcceptanceChildConfig{Role: "worker", ReadyFile: filepath.Join(tmp, "worker.json")})
	workerURL := workerReady.URL + "/deliver"
	t.Cleanup(func() { stopKafkaAcceptanceChild(worker) })
	topic := fmt.Sprintf("two-gateway-%d", time.Now().UnixNano())
	group := topic + "-group"
	apiID, listenPath, secret := "two-gateway-kafka", "/two-gateway/", "shared-acceptance-secret-at-least-32-bytes"
	base := kafkaAcceptanceChildConfig{Role: "gateway", Broker: brokers[0], Topic: topic, Group: group, WorkerURL: workerURL, RedisHost: redisHost, RedisPort: redisPort.Int(), RedisDB: 13, APIID: apiID, ListenPath: listenPath, Secret: secret}
	firstConfig, secondConfig := base, base
	firstConfig.ReadyFile, secondConfig.ReadyFile = filepath.Join(tmp, "gateway-1.json"), filepath.Join(tmp, "gateway-2.json")
	first, firstReady := startKafkaAcceptanceChild(t, executable, firstConfig)
	second, secondReady := startKafkaAcceptanceChild(t, executable, secondConfig)
	t.Cleanup(func() { stopKafkaAcceptanceChild(first); stopKafkaAcceptanceChild(second) })

	saramaConfig := sarama.NewConfig()
	saramaConfig.Version, saramaConfig.Producer.Return.Successes = sarama.V2_0_0_0, true
	producer, err := sarama.NewSyncProducer(brokers, saramaConfig)
	require.NoError(t, err)
	defer producer.Close()
	client, err := sarama.NewClient(brokers, saramaConfig)
	require.NoError(t, err)
	defer client.Close()
	produce := func(value string) {
		_, _, sendErr := producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder(value)})
		require.NoError(t, sendErr)
	}
	produce("first")
	deliveries := waitKafkaAcceptanceDeliveries(t, workerReady.URL, 1)

	owner, nonOwner := identifyKafkaAcceptanceOwner(t, []kafkaAcceptanceChildReady{firstReady, secondReady}, listenPath)
	unauthorized, err := http.Post(nonOwner.URL+listenPath+"worker/kafka/ack", "application/json", nil)
	require.NoError(t, err)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, unauthorized.StatusCode)
	unauthorized.Body.Close()
	response, body := kafkaGatewayPost(t, nonOwner.URL+listenPath+"worker/kafka/ack", nonOwner.Key, fmt.Sprintf(`{"tokens":[%q]}`, deliveries[0].Token))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1 }, 15*time.Second, 100*time.Millisecond)

	produce("second")
	deliveries = waitKafkaAcceptanceDeliveries(t, workerReady.URL, 2)
	staleToken := deliveries[1].Token
	// Group membership may still settle after the first delivery. Resolve the
	// owner of the actual unacknowledged second record immediately before the
	// disruption; retaining the first record's owner can kill the wrong child.
	owner, nonOwner = identifyKafkaAcceptanceOwner(t, []kafkaAcceptanceChildReady{firstReady, secondReady}, listenPath)
	t.Logf("killing current owner %s; survivor ingress %s", owner.URL, nonOwner.URL)
	if owner.URL == firstReady.URL {
		require.NoError(t, first.Process.Kill())
	} else {
		require.NoError(t, second.Process.Kill())
	}
	var recovered bool
	recovered = assert.EventuallyWithT(t, func(c *assert.CollectT) {
		response, getErr := http.Get(workerReady.URL + "/deliveries")
		require.NoError(c, getErr)
		defer response.Body.Close()
		require.NoError(c, json.NewDecoder(response.Body).Decode(&deliveries))
		require.GreaterOrEqual(c, len(deliveries), 3)
	}, 30*time.Second, 100*time.Millisecond)
	if !recovered {
		firstLog, _ := os.ReadFile(firstConfig.ReadyFile + ".log")
		secondLog, _ := os.ReadFile(secondConfig.ReadyFile + ".log")
		for _, gateway := range []kafkaAcceptanceChildReady{firstReady, secondReady} {
			if gateway.URL == owner.URL {
				continue
			}
			response, status := kafkaGatewayGet(t, gateway.URL+listenPath+"worker/kafka/status", gateway.Key)
			t.Logf("survivor status code=%d body=%s", response.StatusCode, status)
		}
		t.Fatalf("no failover redelivery; first gateway:\n%s\nsecond gateway:\n%s", firstLog, secondLog)
	}
	newToken := deliveries[len(deliveries)-1].Token
	require.NotEqual(t, staleToken, newToken)
	response, body = kafkaGatewayPost(t, nonOwner.URL+listenPath+"worker/kafka/ack", nonOwner.Key, fmt.Sprintf(`{"tokens":[%q]}`, staleToken))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, int64(1), gatewayFetchCommittedOffset(t, client, group, topic, 0), "stale pre-failover token advanced Kafka")
	response, body = kafkaGatewayPost(t, nonOwner.URL+listenPath+"worker/kafka/ack", nonOwner.Key, fmt.Sprintf(`{"tokens":[%q]}`, newToken))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 2 }, 15*time.Second, 100*time.Millisecond)
}

func TestKafkaExternalAckTwoGatewayDistributedResetE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker and subprocesses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	kafkaContainer, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = kafkaContainer.Terminate(context.Background()) })
	brokers, err := kafkaContainer.Brokers(ctx)
	require.NoError(t, err)
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisContainer.Terminate(context.Background()) })
	redisHost, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	redisPort, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	executable, err := os.Executable()
	require.NoError(t, err)
	tmp := t.TempDir()
	worker, workerReady := startKafkaAcceptanceChild(t, executable, kafkaAcceptanceChildConfig{Role: "worker", ReadyFile: filepath.Join(tmp, "worker.json")})
	t.Cleanup(func() { stopKafkaAcceptanceChild(worker) })
	topic := fmt.Sprintf("two-gateway-reset-%d", time.Now().UnixNano())
	group := topic + "-group"
	apiID, listenPath, secret := "two-gateway-kafka-reset", "/two-gateway-reset/", "shared-reset-acceptance-secret-at-least-32-bytes"
	base := kafkaAcceptanceChildConfig{Role: "gateway", Broker: brokers[0], Topic: topic, Group: group, WorkerURL: workerReady.URL + "/deliver", RedisHost: redisHost, RedisPort: redisPort.Int(), RedisDB: 12, APIID: apiID, ListenPath: listenPath, Secret: secret}
	firstConfig, secondConfig := base, base
	firstConfig.ReadyFile, secondConfig.ReadyFile = filepath.Join(tmp, "gateway-1.json"), filepath.Join(tmp, "gateway-2.json")
	first, firstReady := startKafkaAcceptanceChild(t, executable, firstConfig)
	second, secondReady := startKafkaAcceptanceChild(t, executable, secondConfig)
	t.Cleanup(func() { stopKafkaAcceptanceChild(first); stopKafkaAcceptanceChild(second) })

	cfg := sarama.NewConfig()
	cfg.Version, cfg.Producer.Return.Successes = sarama.V2_0_0_0, true
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	defer producer.Close()
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	defer client.Close()
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("reset-me")})
	require.NoError(t, err)
	deliveries := waitKafkaAcceptanceDeliveries(t, workerReady.URL, 1)
	old := deliveries[0]

	// Either authenticated member is a valid ingress for the shared durable
	// acknowledgment route. The owning member performs the Kafka commit.
	response, body := kafkaGatewayPost(t, secondReady.URL+listenPath+"worker/kafka/ack", secondReady.Key, fmt.Sprintf(`{"tokens":[%q]}`, old.Token))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1 }, 15*time.Second, 100*time.Millisecond)

	planPayload := fmt.Sprintf(`{"consumer_group":%q,"reason":"two gateway distributed replay","targets":[{"topic":%q,"partition":0,"offset":0}]}`, group, topic)
	oldResponse, _ := kafkaGatewayPost(t, firstReady.URL+listenPath+"worker/kafka/offset/reset/plan", firstReady.Key, planPayload)
	require.Contains(t, []int{http.StatusNotFound, http.StatusForbidden}, oldResponse.StatusCode)
	controlPath := fmt.Sprintf("/tyk/streams/%s/worker/kafka/%s_worker_gateway/offset/reset", apiID, apiID)
	for _, bad := range []string{"", "wrong-admin-secret"} {
		denied, _ := kafkaGatewayControlPost(t, firstReady.URL+controlPath+"/plan", bad, planPayload)
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, denied.StatusCode)
	}
	response, body = kafkaGatewayControlPost(t, firstReady.URL+controlPath+"/plan", secret, planPayload)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	var plan streamkafka.ResetPlan
	require.NoError(t, json.Unmarshal(body, &plan))
	require.NotEmpty(t, plan.ID)
	response, body = kafkaGatewayControlPost(t, firstReady.URL+controlPath+"/execute", secret, fmt.Sprintf(`{"plan_id":%q}`, plan.ID))
	if response.StatusCode != http.StatusAccepted {
		firstLog, _ := os.ReadFile(firstConfig.ReadyFile + ".log")
		secondLog, _ := os.ReadFile(secondConfig.ReadyFile + ".log")
		redisClient := redis.NewClient(&redis.Options{Addr: net.JoinHostPort(redisHost, redisPort.Port()), DB: 12})
		audits, _ := redisClient.LRange(ctx, "tyk:kafka:reset:audit", 0, -1).Result()
		keys, _ := redisClient.Keys(ctx, "tyk:kafka:reset*").Result()
		_ = redisClient.Close()
		t.Fatalf("reset execute status=%d body=%s\nreset keys=%v\naudits=%v\nfirst gateway:\n%s\nsecond gateway:\n%s", response.StatusCode, body, keys, audits, firstLog, secondLog)
	}
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 0 }, 20*time.Second, 100*time.Millisecond)
	deliveries = waitKafkaAcceptanceDeliveries(t, workerReady.URL, 2)
	replay := deliveries[len(deliveries)-1]
	require.NotEqual(t, old.Token, replay.Token)
	require.NotEqual(t, old.DeliveryID, replay.DeliveryID)
	require.NotEmpty(t, replay.ReplayID)
	require.NotEqual(t, old.ReplayID, replay.ReplayID)

	// Distributed ingress durably accepts the stale token, but the new owner
	// must fence it and leave the reset watermark untouched.
	response, body = kafkaGatewayPost(t, secondReady.URL+listenPath+"worker/kafka/ack", secondReady.Key, fmt.Sprintf(`{"tokens":[%q]}`, old.Token))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, int64(0), gatewayFetchCommittedOffset(t, client, group, topic, 0))
	response, body = kafkaGatewayPost(t, secondReady.URL+listenPath+"worker/kafka/ack", secondReady.Key, fmt.Sprintf(`{"tokens":[%q]}`, replay.Token))
	require.Equal(t, http.StatusAccepted, response.StatusCode, string(body))
	require.Eventually(t, func() bool { return gatewayFetchCommittedOffset(t, client, group, topic, 0) == 1 }, 15*time.Second, 100*time.Millisecond)
}

func startKafkaAcceptanceChild(t *testing.T, executable string, config kafkaAcceptanceChildConfig) (*exec.Cmd, kafkaAcceptanceChildReady) {
	t.Helper()
	payload, err := json.Marshal(config)
	require.NoError(t, err)
	// The same child entry point backs both short acceptance tests and the
	// opt-in 24-hour soak. Parent tests own termination, so the child ceiling
	// must exceed the longest supported parent run.
	cmd := exec.Command(executable, "-test.run=^TestKafkaAcceptanceChildProcess$", "-test.timeout=26h")
	cmd.Env = append(os.Environ(), "TYK_KAFKA_ACCEPTANCE_CHILD="+string(payload))
	logFile, err := os.Create(config.ReadyFile + ".log")
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = logFile.Close() })
	var ready kafkaAcceptanceChildReady
	require.Eventually(t, func() bool {
		data, readErr := os.ReadFile(config.ReadyFile)
		return readErr == nil && json.Unmarshal(data, &ready) == nil && ready.URL != ""
	}, 30*time.Second, 50*time.Millisecond, "child did not become ready; log: %s", config.ReadyFile+".log")
	return cmd, ready
}

func stopKafkaAcceptanceChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
	}
}

func waitKafkaAcceptanceDeliveries(t *testing.T, workerURL string, count int) []gatewayKafkaDelivery {
	t.Helper()
	var deliveries []gatewayKafkaDelivery
	require.Eventually(t, func() bool {
		response, err := http.Get(workerURL + "/deliveries")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return json.NewDecoder(response.Body).Decode(&deliveries) == nil && len(deliveries) >= count
	}, 30*time.Second, 100*time.Millisecond)
	return deliveries
}

func identifyKafkaAcceptanceOwner(t *testing.T, gateways []kafkaAcceptanceChildReady, listenPath string) (kafkaAcceptanceChildReady, kafkaAcceptanceChildReady) {
	t.Helper()
	var ownerIndex = -1
	require.Eventually(t, func() bool {
		for i, gateway := range gateways {
			response, body := kafkaGatewayGet(t, gateway.URL+listenPath+"worker/kafka/status", gateway.Key)
			if response.StatusCode == http.StatusOK && string(body) != "" && containsJSONInFlight(body) {
				ownerIndex = i
				return true
			}
		}
		return false
	}, 15*time.Second, 100*time.Millisecond)
	require.NotEqual(t, -1, ownerIndex)
	return gateways[ownerIndex], gateways[1-ownerIndex]
}

func containsJSONInFlight(body []byte) bool {
	var status struct {
		InFlight int `json:"in_flight"`
	}
	return json.Unmarshal(body, &status) == nil && status.InFlight > 0
}

// TestKafkaAcceptanceChildProcess is a reusable child-process entry point for
// the two-Gateway acceptance topology. It is inert during ordinary test runs.
// A parent invokes the test binary with -test.run=^TestKafkaAcceptanceChildProcess$
// and TYK_KAFKA_ACCEPTANCE_CHILD containing kafkaAcceptanceChildConfig.
func TestKafkaAcceptanceChildProcess(t *testing.T) {
	raw := os.Getenv("TYK_KAFKA_ACCEPTANCE_CHILD")
	if raw == "" {
		t.Skip("subprocess helper")
	}
	var child kafkaAcceptanceChildConfig
	if err := json.Unmarshal([]byte(raw), &child); err != nil {
		t.Fatal(err)
	}
	switch child.Role {
	case "worker":
		runKafkaAcceptanceWorkerChild(t, child)
	case "gateway":
		runKafkaAcceptanceGatewayChild(t, child)
	default:
		t.Fatalf("unknown child role %q", child.Role)
	}
}

func runKafkaAcceptanceWorkerChild(t *testing.T, child kafkaAcceptanceChildConfig) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var deliveries []gatewayKafkaDelivery
	mux := http.NewServeMux()
	mux.HandleFunc("/deliver", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		deliveries = appendBoundedKafkaDeliveries(deliveries, gatewayKafkaDelivery{Token: r.Header.Get("Tyk-Kafka-Ack-Token"), DeliveryID: r.Header.Get("Tyk-Kafka-Delivery-ID"), ReplayID: r.Header.Get("Tyk-Kafka-Replay-ID"), Topic: r.Header.Get("Tyk-Kafka-Topic"), Partition: r.Header.Get("Tyk-Kafka-Partition"), Offset: r.Header.Get("Tyk-Kafka-Offset"), Body: string(body)})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/deliveries", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		result := append([]gatewayKafkaDelivery(nil), deliveries...)
		mu.Unlock()
		if raw := r.URL.Query().Get("tail"); raw != "" {
			if tail, parseErr := strconv.Atoi(raw); parseErr == nil && tail > 0 && tail < len(result) {
				result = result[len(result)-tail:]
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	writeKafkaAcceptanceReady(t, child.ReadyFile, kafkaAcceptanceChildReady{URL: "http://" + listener.Addr().String()})
	waitKafkaAcceptanceSignal()
	_ = server.Close()
}

const maxKafkaAcceptanceDeliveries = 4096

func appendBoundedKafkaDeliveries(deliveries []gatewayKafkaDelivery, delivery gatewayKafkaDelivery) []gatewayKafkaDelivery {
	if len(deliveries) == maxKafkaAcceptanceDeliveries {
		copy(deliveries, deliveries[1:])
		deliveries = deliveries[:maxKafkaAcceptanceDeliveries-1]
	}
	return append(deliveries, delivery)
}

func runKafkaAcceptanceGatewayChild(t *testing.T, child kafkaAcceptanceChildConfig) {
	ts := StartTest(func(global *config.Config) {
		global.Streaming.Enabled = true
		global.Secret = child.Secret
		global.Storage.Type = "redis"
		global.Storage.Host = child.RedisHost
		global.Storage.Port = child.RedisPort
		global.Storage.Database = child.RedisDB
	}, TestConfig{TestHTTPListen: "127.0.0.1:0"})
	defer ts.Close()
	loadedAPIID := child.APIID
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = child.APIID
		spec.Proxy.ListenPath = child.ListenPath
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
		spec.IsOAS = true
		spec.OAS = kafkaManualCommitDistributedOAS(t, child.Broker, child.Topic, child.Group, child.WorkerURL)
		spec.OAS.Fill(*spec.APIDefinition)
		loadedAPIID = spec.APIID
	})
	key := kafkaGatewayLongLivedSession(t, ts, loadedAPIID, []string{"kafka:ack", "kafka:status", "kafka:offset-reset"})
	writeKafkaAcceptanceReady(t, child.ReadyFile, kafkaAcceptanceChildReady{URL: ts.URL, Key: key})
	waitKafkaAcceptanceSignal()
}

func kafkaGatewayLongLivedSession(t *testing.T, ts *Test, apiID string, permissions []string) string {
	t.Helper()
	key := ts.Gw.generateToken("default", "")
	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{apiID: {APIID: apiID, Versions: []string{"Default"}}}
	session.MetaData["kafka_permissions"] = permissions
	hashKeys := ts.Gw.GetConfig().HashKeys
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(key, hashKeys), session, int64((26*time.Hour)/time.Second), hashKeys))
	return key
}

func kafkaManualCommitDistributedOAS(t *testing.T, broker, topic, group, worker string) oas.OAS {
	result := kafkaManualCommitOAS(t, broker, topic, group, worker)
	streamsRoot := result.Extensions[streams.ExtensionTykStreaming].(map[string]interface{})
	stream := streamsRoot["streams"].(map[string]interface{})["worker"].(map[string]interface{})
	input := stream["input"].(map[string]interface{})["tyk_kafka"].(map[string]interface{})
	// Crash-failover acceptance must complete inside its bounded 30 second
	// assertion. Production defaults deliberately favor transient network
	// tolerance (45s sessions), so this fixture uses a valid faster liveness
	// profile rather than weakening SIGKILL into graceful leave-group shutdown.
	input["session_timeout"] = "6s"
	input["heartbeat_interval"] = "2s"
	input["acknowledgment"].(map[string]interface{})["routing"] = "distributed"
	return result
}

func writeKafkaAcceptanceReady(t *testing.T, path string, ready kafkaAcceptanceChildReady) {
	t.Helper()
	payload, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitKafkaAcceptanceSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

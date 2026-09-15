package kafka

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

func franzGoGoroutineCount() int {
	var stacks bytes.Buffer
	if profile := pprof.Lookup("goroutine"); profile != nil {
		_ = profile.WriteTo(&stacks, 2)
	}
	count := 0
	for _, goroutine := range strings.Split(stacks.String(), "\n\n") {
		if strings.Contains(goroutine, "github.com/twmb/franz-go/pkg/kgo") {
			count++
		}
	}
	return count
}

// brokerSocketCount returns the number of this process's open TCP socket file
// descriptors whose local or remote port belongs to one of the test brokers.
// Scoping by broker port avoids comparing the process-wide descriptor count,
// which is inherently noisy when unrelated tests open files concurrently.
func brokerSocketCount(brokers []string) (int, error) {
	ports := make(map[string]struct{}, len(brokers))
	for _, broker := range brokers {
		_, port, err := net.SplitHostPort(broker)
		if err != nil {
			return 0, fmt.Errorf("parse broker %q: %w", broker, err)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("parse broker port %q: %w", port, err)
		}
		ports[fmt.Sprintf("%04X", portNumber)] = struct{}{}
	}

	inodes := map[string]struct{}{}
	for _, table := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		contents, err := os.ReadFile(table)
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(contents), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			local := strings.Split(fields[1], ":")
			remote := strings.Split(fields[2], ":")
			if len(local) != 2 || len(remote) != 2 {
				continue
			}
			_, localMatches := ports[strings.ToUpper(local[1])]
			_, remoteMatches := ports[strings.ToUpper(remote[1])]
			if localMatches || remoteMatches {
				inodes[fields[9]] = struct{}{}
			}
		}
	}

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil { // An FD can close between ReadDir and Readlink.
			continue
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		if _, matches := inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")]; matches {
			count++
		}
	}
	return count, nil
}

// TestExternalAcknowledgmentReloadReleasesConsumer proves lifecycle ownership
// against Kafka itself across repeated reload cycles: each stream becomes the
// sole live group member, leaves before its replacement joins, and the
// uncommitted record is safely redelivered every time.
func TestExternalAcknowledgmentReloadReleasesConsumer(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	if runtime.GOOS != "linux" {
		t.Skip("broker-scoped socket lifecycle evidence requires Linux /proc")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	topic, group := fmt.Sprintf("reload-%d", time.Now().UnixNano()), fmt.Sprintf("reload-group-%d", time.Now().UnixNano())
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_0_0_0
	cfg.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, cfg)
	require.NoError(t, err)
	defer producer.Close()
	_, _, err = producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder("uncommitted")})
	require.NoError(t, err)
	admin, err := sarama.NewClusterAdmin(brokers, cfg)
	require.NoError(t, err)
	defer admin.Close()
	client, err := sarama.NewClient(brokers, cfg)
	require.NoError(t, err)
	defer client.Close()

	var mu sync.Mutex
	var offsets []int64
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset, parseErr := strconv.ParseInt(r.Header.Get("Tyk-Kafka-Offset"), 10, 64)
		if parseErr != nil {
			http.Error(w, "offset", http.StatusBadRequest)
			return
		}
		mu.Lock()
		offsets = append(offsets, offset)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	componentID := fmt.Sprintf("reload-component-%d", time.Now().UnixNano())
	provider, err := NewSharedAckSigningKeyProvider("test", map[string][]byte{"test": []byte("reload lifecycle shared signing secret")})
	require.NoError(t, err)
	require.NoError(t, GlobalRuntimeAckKeyRegistry.Configure(componentID, provider))
	defer GlobalRuntimeAckKeyRegistry.Remove(componentID)

	build := func() *service.Stream {
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
      Tyk-Kafka-Offset: '${! @kafka_offset }'
`, brokers[0], topic, group, componentID, downstream.URL)))
		stream, buildErr := builder.Build()
		require.NoError(t, buildErr)
		return stream
	}
	memberCount := func() int {
		descriptions, describeErr := admin.DescribeConsumerGroups([]string{group})
		if describeErr != nil || len(descriptions) != 1 {
			return -1
		}
		return len(descriptions[0].Members)
	}
	run := func(stream *service.Stream) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = stream.Run(ctx)
		}()
		return done
	}
	stop := func(stream *service.Stream, runDone <-chan struct{}) {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		require.NoError(t, stream.Stop(stopCtx))
		select {
		case <-runDone:
		case <-stopCtx.Done():
			t.Fatalf("stream.Run goroutine did not exit after Stop: %v", stopCtx.Err())
		}
	}

	const cycles = 4
	// Sarama opens admin and metadata connections lazily. Prime the long-lived
	// fixture clients before capturing the socket baseline so their own sockets
	// are not mistaken for connector leaks after the first reload cycle.
	require.NoError(t, client.RefreshMetadata(topic))
	_, err = admin.ListConsumerGroups()
	require.NoError(t, err)
	baselineKafkaGoroutines := franzGoGoroutineCount()
	baselineBrokerSockets, err := brokerSocketCount(brokers)
	require.NoError(t, err)
	for cycle := 1; cycle <= cycles; cycle++ {
		stream := build()
		runDone := run(stream)
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(offsets) >= cycle
		}, 30*time.Second, 100*time.Millisecond, "cycle %d did not deliver", cycle)
		require.Eventually(t, func() bool { return memberCount() == 1 }, 20*time.Second, 100*time.Millisecond,
			"cycle %d did not have exactly one consumer", cycle)
		require.Eventually(t, func() bool { return franzGoGoroutineCount() > baselineKafkaGoroutines }, 5*time.Second, 50*time.Millisecond,
			"cycle %d did not expose a live franz-go client goroutine", cycle)
		require.Eventually(t, func() bool {
			count, countErr := brokerSocketCount(brokers)
			return countErr == nil && count > baselineBrokerSockets
		}, 5*time.Second, 50*time.Millisecond, "cycle %d did not open a Kafka broker socket", cycle)

		stop(stream, runDone)
		require.Eventually(t, func() bool { return memberCount() == 0 }, 20*time.Second, 100*time.Millisecond,
			"cycle %d leaked Kafka group membership", cycle)
		require.Eventually(t, func() bool { return franzGoGoroutineCount() == baselineKafkaGoroutines }, 10*time.Second, 100*time.Millisecond,
			"cycle %d leaked franz-go client goroutines: baseline=%d current=%d", cycle, baselineKafkaGoroutines, franzGoGoroutineCount())
		require.Eventually(t, func() bool {
			count, countErr := brokerSocketCount(brokers)
			return countErr == nil && count == baselineBrokerSockets
		}, 10*time.Second, 100*time.Millisecond, "cycle %d leaked Kafka broker sockets: baseline=%d", cycle, baselineBrokerSockets)
		require.Eventually(t, func() bool {
			_, registered := GlobalControllerRegistry.StatusSnapshot(ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: componentID}, 1)
			return !registered
		}, 5*time.Second, 50*time.Millisecond, "cycle %d leaked its controller registration", cycle)
		require.Equal(t, int64(-1), fetchCommittedOffset(t, client, group, topic, 0),
			"cycle %d committed an unacknowledged record", cycle)
	}
	mu.Lock()
	require.Equal(t, []int64{0, 0, 0, 0}, offsets[:cycles], "every replacement must receive the uncommitted record")
	mu.Unlock()
}

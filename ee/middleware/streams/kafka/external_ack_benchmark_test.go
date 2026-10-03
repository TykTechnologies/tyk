package kafka

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Jeffail/checkpoint"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

func BenchmarkKafkaAcknowledgmentBookkeepingComparison(b *testing.B) {
	outputAck := func(b *testing.B) {
		window := checkpoint.NewUncapped[*kgo.Record]()
		record := &kgo.Record{Topic: "employees", Partition: 0, Value: []byte("employee-update")}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			record.Offset = int64(i)
			release := window.Track(record, 1)
			_ = release()
		}
	}
	// kafka_franz and tyk_kafka output_ack deliberately use the same Bento
	// checkpoint primitive. Separate names make regression comparisons explicit.
	b.Run("standard_kafka_franz_output_ack", outputAck)
	b.Run("tyk_kafka_output_ack", outputAck)
	b.Run("tyk_kafka_external_ack", func(b *testing.B) {
		controller := benchmarkController(b, 1)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			message := service.NewMessage([]byte("employee-update"))
			if err := controller.Track(&kgo.Record{Topic: "employees", Partition: 0, Offset: int64(i), Value: []byte("employee-update")}, message); err != nil {
				b.Fatal(err)
			}
			token, _ := message.MetaGet("tyk_kafka_ack_token")
			if _, err := controller.Acknowledge(context.Background(), []string{token}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

type benchmarkCommitter struct{}

func (benchmarkCommitter) CommitRecords(context.Context, ...*kgo.Record) error { return nil }

func benchmarkController(b *testing.B, window int) *ExternalAckController {
	b.Helper()
	codec, err := NewAckTokenCodec("benchmark", map[string][]byte{"benchmark": []byte("a sufficiently long benchmark signing key")})
	if err != nil {
		b.Fatal(err)
	}
	config := defaultAcknowledgmentConfig()
	config.Mode, config.CheckpointLimit = AcknowledgmentModeExternal, window
	config.MaxInFlight, config.MaxInFlightBytes = window, uint64(window*256)
	config.CommitInterval, config.CommitBatchSize = time.Millisecond, 1
	controller, err := NewExternalAckController(ControllerKey{APIID: "bench", StreamID: "stream", ComponentID: "input"}, "cluster", "replay", codec, config)
	if err != nil {
		b.Fatal(err)
	}
	controller.SetCommitter(benchmarkCommitter{})
	b.Cleanup(controller.Close)
	return controller
}

func BenchmarkExternalAckOutOfOrderGapClosure(b *testing.B) {
	const window = 256
	controller := benchmarkController(b, window)
	tokens := make([]string, window)
	b.ReportAllocs()
	b.ResetTimer()
	for cycle := 0; cycle < b.N; cycle++ {
		base := int64(cycle * window)
		for i := range tokens {
			message := service.NewMessage([]byte("employee-update"))
			if err := controller.Track(&kgo.Record{Topic: "employees", Partition: 0, Offset: base + int64(i), Value: []byte("employee-update")}, message); err != nil {
				b.Fatal(err)
			}
			tokens[i], _ = message.MetaGet("tyk_kafka_ack_token")
		}
		reversed := make([]string, window)
		for i := range tokens {
			reversed[i] = tokens[window-1-i]
		}
		if _, err := controller.Acknowledge(context.Background(), reversed); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N*window), "records")
}

func BenchmarkInMemoryDistributedAckRouting(b *testing.B) {
	route := AckRoute{Key: ControllerKey{APIID: "bench", StreamID: "stream", ComponentID: "input"}, Topic: "employees", Partition: 0}
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{MaxEntries: 1024, MaxBytes: 1 << 20})
	assignment, err := transport.Assign(context.Background(), route, "gateway", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("ack-%d", i)
		if err := transport.AppendBatch(context.Background(), []AckCommand{{ID: id, Route: route, Token: "signed-token"}}); err != nil {
			b.Fatal(err)
		}
		deliveries, err := transport.Claim(context.Background(), assignment, "worker", 1, time.Second, time.Now())
		if err != nil || len(deliveries) != 1 {
			b.Fatalf("claim: %v (%d)", err, len(deliveries))
		}
		if err := transport.Complete(context.Background(), assignment, id); err != nil {
			b.Fatal(err)
		}
	}
}

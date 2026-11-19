package otel

import (
	"context"
	"testing"

	"github.com/TykTechnologies/opentelemetry/metric/metrictest"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
)

func TestKafkaStreamMetricsExporterValues(t *testing.T) {
	provider := metrictest.NewProvider(t)
	instruments := NewMetricInstruments(provider, logrus.New())
	instruments.RecordKafkaStream(context.Background(), "api", "stream", "component", map[string]uint64{"delivered": 3, "token-from-user": 99}, map[string]int64{"in_flight": 2, "partition-123": 99})
	attrs := []attribute.KeyValue{attribute.String("api", "api"), attribute.String("stream", "stream"), attribute.String("component", "component")}
	events := provider.FindMetric(t, "tyk.streams.kafka.events")
	metrictest.AssertSum(t, events, int64(3))
	metrictest.AssertSumWithAttrs(t, events, int64(3), append(attrs, attribute.String("kind", "delivered"))...)
	state := provider.FindMetric(t, "tyk.streams.kafka.state")
	metrictest.AssertGauge(t, state, float64(2))
}

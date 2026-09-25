package otel

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestKafkaObservabilityAssetsUseExportedMetrics(t *testing.T) {
	const assetRoot = "../../docs/architecture/assets/tt17103/"
	rules, err := os.ReadFile(assetRoot + "prometheus-rules.yaml")
	require.NoError(t, err)
	var ruleDocument map[string]any
	require.NoError(t, yaml.Unmarshal(rules, &ruleDocument))
	require.NotEmpty(t, ruleDocument["groups"])

	dashboard, err := os.ReadFile(assetRoot + "grafana-dashboard.json")
	require.NoError(t, err)
	var dashboardDocument map[string]any
	require.NoError(t, json.Unmarshal(dashboard, &dashboardDocument))
	require.NotEmpty(t, dashboardDocument["panels"])

	metricPattern := regexp.MustCompile(`tyk_streams_kafka_[a-zA-Z0-9_:]+`)
	allowed := map[string]struct{}{
		"tyk_streams_kafka_events_total": {}, // Prometheus counter export of tyk.streams.kafka.events.
		"tyk_streams_kafka_state":        {}, // Prometheus gauge export of tyk.streams.kafka.state.
	}
	for _, contents := range [][]byte{rules, dashboard} {
		matches := metricPattern.FindAll(contents, -1)
		require.NotEmpty(t, matches)
		for _, match := range matches {
			_, ok := allowed[string(match)]
			require.Truef(t, ok, "asset references unknown Kafka metric %q", match)
		}
	}
	emittedKinds := map[string]struct{}{
		"delivered": {}, "ack_applied": {}, "commit_attempts": {}, "commit_failures": {},
		"reset_executions": {}, "reset_failures": {}, "in_flight": {}, "pending_commits": {},
		"paused_partitions": {}, "router_backlog": {}, "router_pending": {}, "router_dead_letters": {},
	}
	kindPattern := regexp.MustCompile(`kind=~?\\?"([^"\\]+)`)
	kindReferences := 0
	for _, contents := range [][]byte{rules, dashboard} {
		for _, match := range kindPattern.FindAllSubmatch(contents, -1) {
			for _, kind := range strings.Split(string(match[1]), "|") {
				kindReferences++
				_, ok := emittedKinds[kind]
				require.Truef(t, ok, "asset references Kafka kind %q that the manager does not emit", kind)
			}
		}
	}
	require.Positive(t, kindReferences)

	// Keep the asset contract tied to the actual OTel instruments rather than
	// allowing dashboard-only metric names to drift silently.
	source, err := os.ReadFile("metrics_instrument.go")
	require.NoError(t, err)
	require.Contains(t, string(source), `NewCounter("tyk.streams.kafka.events"`)
	require.Contains(t, string(source), `NewGauge("tyk.streams.kafka.state"`)
}

package streams

import (
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatewayAckSigningProviderEnforcesOverlapAndSecretRefs(t *testing.T) {
	var cfg config.Config
	cfg.Secrets = map[string]string{"old-ref": "old-secret-at-least-thirty-two-bytes-long", "new-ref": "new-secret-at-least-thirty-two-bytes-long"}
	cfg.KafkaAcknowledgmentSigning.ActiveKeyID = "new"
	cfg.KafkaAcknowledgmentSigning.Keys = map[string]string{"old": "old-ref", "new": "new-ref"}
	cfg.KafkaAcknowledgmentSigning.RotationOverlapSeconds = int64((time.Hour + 30*time.Second) / time.Second)
	stream := map[string]interface{}{"input": map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"token_ttl": "1h"}}}}
	_, err := gatewayAckSigningProvider(cfg, stream)
	require.NoError(t, err)
	cfg.KafkaAcknowledgmentSigning.RotationOverlapSeconds = 1
	_, err = gatewayAckSigningProvider(cfg, stream)
	require.Error(t, err)
}

func TestGatewayAckSigningProviderRejectsUnsafeFallback(t *testing.T) {
	stream := map[string]interface{}{}
	for _, tc := range []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"short", "short-shared-secret"},
		{"default", config.Default.Secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gatewayAckSigningProvider(config.Config{Secret: tc.secret}, stream)
			require.Error(t, err)
		})
	}

	_, err := gatewayAckSigningProvider(config.Config{Secret: "unique-gateway-secret-at-least-32-bytes-long"}, stream)
	require.NoError(t, err, "existing installations with a strong unique Gateway secret remain compatible")
}

func TestGatewayAckSigningProviderRejectsPartialOrWeakExplicitConfiguration(t *testing.T) {
	stream := map[string]interface{}{}
	cfg := config.Config{}
	cfg.KafkaAcknowledgmentSigning.ActiveKeyID = "current"
	_, err := gatewayAckSigningProvider(cfg, stream)
	require.ErrorContains(t, err, "configured together")

	cfg.KafkaAcknowledgmentSigning.Keys = map[string]string{"current": "ack-key"}
	cfg.KafkaAcknowledgmentSigning.RotationOverlapSeconds = int64((24*time.Hour + 30*time.Second) / time.Second)
	cfg.Secrets = map[string]string{"ack-key": "weak"}
	_, err = gatewayAckSigningProvider(cfg, stream)
	require.Error(t, err, "explicit roots retain the 32-byte minimum")

	cfg.KafkaAcknowledgmentSigning.ActiveKeyID = ""
	_, err = gatewayAckSigningProvider(cfg, stream)
	require.ErrorContains(t, err, "configured together")
}

func TestPrepareKafkaAcknowledgmentComponents(t *testing.T) {
	directAck := map[string]interface{}{"mode": "external_ack"}
	brokerAck := map[string]interface{}{"mode": "external_ack", "component_id": "audit"}
	config := map[string]interface{}{
		"input": map[string]interface{}{
			"tyk_kafka": map[string]interface{}{"acknowledgment": directAck},
			"broker": map[string]interface{}{"inputs": []interface{}{
				map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": brokerAck}},
				map[string]interface{}{"kafka_franz": map[string]interface{}{}},
			}},
		},
	}

	components := PrepareKafkaAcknowledgmentComponents(config, "api", "employees")
	require.Equal(t, []string{"api_employees_input-0", "api_employees_audit"}, components)
	assert.Equal(t, components[0], directAck["component_id"])
	assert.Equal(t, components[1], brokerAck["component_id"])
	assert.Equal(t, components, PrepareKafkaAcknowledgmentComponents(config, "api", "employees"), "preparation must be stable across validation and stream creation")
}

func TestDistributedKafkaAcknowledgmentComponents(t *testing.T) {
	stream := map[string]interface{}{"input": map[string]interface{}{"broker": map[string]interface{}{"inputs": []interface{}{
		map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"mode": "external_ack", "routing": "distributed", "component_id": "distributed"}}},
		map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"mode": "external_ack", "component_id": "default-distributed"}}},
		map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"mode": "external_ack", "routing": "local", "component_id": "local"}}},
	}}}}
	require.Equal(t, []string{"distributed", "default-distributed"}, DistributedKafkaAcknowledgmentComponents(stream))
}

func TestPrepareKafkaAcknowledgmentComponentsIgnoresOutputAck(t *testing.T) {
	config := map[string]interface{}{"input": map[string]interface{}{
		"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"mode": "output_ack"}},
	}}
	assert.Empty(t, PrepareKafkaAcknowledgmentComponents(config, "api", "stream"))
}

func TestKafkaAcknowledgmentComponentsByRouting(t *testing.T) {
	config := map[string]interface{}{"input": map[string]interface{}{"tyk_kafka": map[string]interface{}{"acknowledgment": map[string]interface{}{"mode": "external_ack", "routing": "local"}}}}
	PrepareKafkaAcknowledgmentComponents(config, "api", "stream")
	assert.Equal(t, []string{"api_stream_input-0"}, LocalKafkaAcknowledgmentComponents(config))
	assert.Empty(t, DistributedKafkaAcknowledgmentComponents(config))
}

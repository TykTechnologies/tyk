package kafka

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/warpstreamlabs/bento/public/service"
)

const acknowledgmentConfigTestBase = `
seed_brokers: [localhost:9092]
topics: [employees]
`

func parseAcknowledgmentTestReader(t *testing.T, yaml string) (*franzKafkaReader, error) {
	t.Helper()
	conf, err := franzKafkaInputConfig().ParseYAML(acknowledgmentConfigTestBase+yaml, nil)
	if err != nil {
		return nil, err
	}
	return newFranzKafkaReaderFromConfig(conf, service.MockResources())
}

func TestAcknowledgmentConfigDefaultsToOutputAck(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, "")
	require.NoError(t, err)
	require.Equal(t, defaultAcknowledgmentConfig(), reader.acknowledgment)
	require.Equal(t, 1024, reader.checkpointLimit)
}

func TestAcknowledgmentConfigParsesExternalAck(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, `
consumer_group: vinci-employees
acknowledgment:
  mode: external_ack
  checkpoint_limit: 256
  max_in_flight: 10000
  max_in_flight_bytes: 256MiB
  ack_deadline: 30m
  missing_ack_policy: pause
  token_ttl: 24h
  routing: local
  component_id: employee-import
  commit_interval: 250ms
  commit_batch_size: 128
`)
	require.NoError(t, err)
	require.Equal(t, AcknowledgmentConfig{
		Mode:                      AcknowledgmentModeExternal,
		CheckpointLimit:           256,
		MaxInFlight:               10000,
		MaxInFlightBytes:          256 * 1024 * 1024,
		AckDeadline:               30 * time.Minute,
		MissingAckPolicy:          "pause",
		TokenTTL:                  24 * time.Hour,
		Routing:                   "local",
		ComponentID:               "employee-import",
		CommitInterval:            250 * time.Millisecond,
		CommitBatchSize:           128,
		RedeliveryMaxAttempts:     8,
		RedeliveryMaxAge:          24 * time.Hour,
		RedeliveryBackoff:         time.Second,
		RedeliveryMaxBackoff:      time.Minute,
		RedeliveryExhaustedPolicy: "pause",
	}, reader.acknowledgment)
	require.Equal(t, 256, reader.checkpointLimit)
}

func TestAcknowledgmentConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "external ack requires consumer group",
			config: `acknowledgment:
  mode: external_ack
`,
			wantErr: "requires consumer_group",
		},
		{
			name: "external ack rejects top-level checkpoint limit",
			config: `consumer_group: workers
checkpoint_limit: 5
acknowledgment:
  mode: external_ack
`,
			wantErr: "top-level checkpoint_limit",
		},
		{
			name: "deprecated switch cannot silently disable commits",
			config: `consumer_group: workers
disable_auto_commit: true
`,
			wantErr: "disable_auto_commit is deprecated",
		},
		{
			name: "explicit partitions conflict with group",
			config: `topics: [employees:0]
consumer_group: workers
acknowledgment:
  mode: external_ack
`,
			wantErr: "incompatible with explicit topic partitions",
		},
		{
			name: "checkpoint limit is positive",
			config: `consumer_group: workers
acknowledgment:
  mode: external_ack
  checkpoint_limit: 0
`,
			wantErr: "acknowledgment.checkpoint_limit",
		},
		{
			name: "global record limit is positive",
			config: `acknowledgment:
  max_in_flight: 0
`,
			wantErr: "acknowledgment.max_in_flight",
		},
		{
			name: "global byte limit is positive",
			config: `acknowledgment:
  max_in_flight_bytes: 0B
`,
			wantErr: "acknowledgment.max_in_flight_bytes",
		},
		{
			name: "ack deadline is positive",
			config: `acknowledgment:
  ack_deadline: 0s
`,
			wantErr: "acknowledgment.ack_deadline",
		},
		{
			name: "token ttl is positive",
			config: `acknowledgment:
  token_ttl: 0s
`,
			wantErr: "acknowledgment.token_ttl",
		},
		{
			name: "token remains valid through acknowledgment deadline",
			config: `acknowledgment:
  ack_deadline: 2h
  token_ttl: 1h
`,
			wantErr: "token_ttl must be greater than or equal",
		},
		{
			name: "commit interval is positive",
			config: `acknowledgment:
  commit_interval: 0s
`,
			wantErr: "acknowledgment.commit_interval",
		},
		{
			name: "commit batch is positive",
			config: `acknowledgment:
  commit_batch_size: 0
`,
			wantErr: "acknowledgment.commit_batch_size",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseAcknowledgmentTestReader(t, test.config)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestDeprecatedDisableAutoCommitAcceptedWithExplicitExternalAck(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, `
consumer_group: workers
disable_auto_commit: true
acknowledgment:
  mode: external_ack
`)
	require.NoError(t, err)
	require.Equal(t, AcknowledgmentModeExternal, reader.acknowledgment.Mode)
}

func TestKafkaGroupLivenessConfig(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, `
consumer_group: workers
session_timeout: 6s
heartbeat_interval: 2s
`)
	require.NoError(t, err)
	require.Equal(t, 6*time.Second, reader.sessionTimeout)
	require.Equal(t, 2*time.Second, reader.heartbeatInterval)
}

func TestKafkaGroupLivenessConfigDefaults(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, "")
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, reader.sessionTimeout)
	require.Equal(t, 3*time.Second, reader.heartbeatInterval)
}

func TestKafkaGroupLivenessConfigValidation(t *testing.T) {
	for _, test := range []struct {
		name, config, want string
	}{
		{"non-positive session", "session_timeout: 0s\n", "session_timeout must be positive"},
		{"non-positive heartbeat", "heartbeat_interval: 0s\n", "heartbeat_interval must be positive"},
		{"heartbeat too close to session", "session_timeout: 6s\nheartbeat_interval: 4s\n", "at least twice"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseAcknowledgmentTestReader(t, test.config)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestKafkaOffsetResetPrecedenceAndLegacyMapping(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   string
	}{
		{"start_from_oldest: true\n", "earliest"},
		{"start_from_oldest: false\n", "latest"},
		{"start_from_oldest: true\nauto_offset_reset: none\n", "none"},
	} {
		conf, err := franzKafkaInputConfig().ParseYAML(acknowledgmentConfigTestBase+tc.config, nil)
		require.NoError(t, err)
		value, err := getOffsetReset(conf)
		require.NoError(t, err)
		require.Equal(t, tc.want, value)
	}
}

func TestAcknowledgmentMissingAckPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{"dead letter topic required", "acknowledgment:\n  missing_ack_policy: dead_letter\n", "dead_letter_topic is required"},
		{"redelivery attempts positive", "acknowledgment:\n  redelivery_max_attempts: 0\n", "redelivery limits"},
		{"redelivery age positive", "acknowledgment:\n  redelivery_max_age: 0s\n", "redelivery limits"},
		{"redelivery backoff positive", "acknowledgment:\n  redelivery_backoff: 0s\n", "redelivery limits"},
		{"maximum backoff not below initial", "acknowledgment:\n  redelivery_backoff: 2s\n  redelivery_max_backoff: 1s\n", "redelivery limits"},
		{"dead letter exhaustion topic required", "acknowledgment:\n  missing_ack_policy: redeliver\n  redelivery_exhausted_policy: dead_letter\n", "dead_letter_topic is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAcknowledgmentTestReader(t, tc.config)
			require.ErrorContains(t, err, tc.want)
		})
	}

	reader, err := parseAcknowledgmentTestReader(t, "acknowledgment:\n  missing_ack_policy: dead_letter\n  dead_letter_topic: employee-failures\n")
	require.NoError(t, err)
	require.Equal(t, "employee-failures", reader.acknowledgment.DeadLetterTopic)
}

func TestKafkaReaderParsesPartitionAndBalancingOptions(t *testing.T) {
	conf, err := franzKafkaInputConfig().ParseYAML(`
seed_brokers: [localhost:9092]
topics: [employees:1-2]
auto_offset_reset: earliest
checkpoint_limit: 17
preferring_lag: 3
group_balancers: [round_robin, range, sticky, cooperative_sticky, range]
client_id: vinci-client
rack_id: eu-west
regexp_topics: false
reconnect_on_unknown_topic_or_partition: true
multi_header: true
`, nil)
	require.NoError(t, err)
	reader, err := newFranzKafkaReaderFromConfig(conf, service.MockResources())
	require.NoError(t, err)
	require.Equal(t, 17, reader.checkpointLimit)
	require.Equal(t, "vinci-client", reader.clientID)
	require.Equal(t, "eu-west", reader.rackID)
	require.True(t, reader.reconnectOnUnknownTopic)
	require.True(t, reader.multiHeader)
	require.Len(t, reader.topicPartitions["employees"], 2)
	require.Len(t, reader.balancers, 4, "duplicate balancing strategies are ignored")
	require.NotNil(t, reader.preferringLagFn)
}

func TestKafkaReaderRejectsUnknownBalancerAndInvalidBrokers(t *testing.T) {
	for _, yaml := range []string{
		"seed_brokers: ['']\ntopics: [employees]\n",
		"seed_brokers: []\ntopics: [employees]\n",
		"seed_brokers: [localhost:9092]\ntopics: [employees]\ngroup_balancers: [unknown]\n",
	} {
		conf, err := franzKafkaInputConfig().ParseYAML(yaml, nil)
		require.NoError(t, err)
		_, err = newFranzKafkaReaderFromConfig(conf, service.MockResources())
		require.Error(t, err)
	}
}

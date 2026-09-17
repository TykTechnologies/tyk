package kafka

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"

	"github.com/Jeffail/checkpoint"

	"github.com/Jeffail/shutdown"

	"github.com/warpstreamlabs/bento/public/service"
)

var (
	errInvalidSeedBrokerCount = errors.New("you must provide at least one address in 'seed_brokers'")
	errInvalidSeedBrokerValue = errors.New("seed broker address cannot be empty")
)

const (
	AcknowledgmentModeOutput   = "output_ack"
	AcknowledgmentModeExternal = "external_ack"
)

// AcknowledgmentConfig contains the delivery acknowledgment settings used by
// the Kafka input.
type AcknowledgmentConfig struct {
	Mode                      string
	CheckpointLimit           int
	MaxInFlight               int
	MaxInFlightBytes          uint64
	AckDeadline               time.Duration
	MissingAckPolicy          string
	TokenTTL                  time.Duration
	Routing                   string
	ComponentID               string
	CommitInterval            time.Duration
	CommitBatchSize           int
	DeadLetterTopic           string
	RedeliveryMaxAttempts     int
	RedeliveryMaxAge          time.Duration
	RedeliveryBackoff         time.Duration
	RedeliveryMaxBackoff      time.Duration
	RedeliveryExhaustedPolicy string
}

func defaultAcknowledgmentConfig() AcknowledgmentConfig {
	return AcknowledgmentConfig{
		Mode:                      AcknowledgmentModeOutput,
		CheckpointLimit:           1024,
		MaxInFlight:               10000,
		MaxInFlightBytes:          256 * humanize.MiByte,
		AckDeadline:               30 * time.Minute,
		MissingAckPolicy:          "redeliver",
		TokenTTL:                  24 * time.Hour,
		Routing:                   "distributed",
		CommitInterval:            250 * time.Millisecond,
		CommitBatchSize:           128,
		RedeliveryMaxAttempts:     8,
		RedeliveryMaxAge:          24 * time.Hour,
		RedeliveryBackoff:         time.Second,
		RedeliveryMaxBackoff:      time.Minute,
		RedeliveryExhaustedPolicy: "pause",
	}
}

func acknowledgmentField() *service.ConfigField {
	return service.NewObjectField("acknowledgment",
		service.NewStringEnumField("mode", AcknowledgmentModeOutput, AcknowledgmentModeExternal).Default(AcknowledgmentModeOutput),
		service.NewIntField("checkpoint_limit").Default(1024),
		service.NewIntField("max_in_flight").Default(10000),
		service.NewStringField("max_in_flight_bytes").Default("256MiB"),
		service.NewDurationField("ack_deadline").Default("30m"),
		service.NewStringEnumField("missing_ack_policy", "redeliver", "pause", "dead_letter").Default("redeliver"),
		service.NewDurationField("token_ttl").Default("24h"),
		service.NewStringEnumField("routing", "local", "distributed").Default("distributed"),
		service.NewStringField("component_id").Default(""),
		service.NewDurationField("commit_interval").Default("250ms"),
		service.NewIntField("commit_batch_size").Default(128),
		service.NewStringField("dead_letter_topic").Default(""),
		service.NewIntField("redelivery_max_attempts").Default(8),
		service.NewDurationField("redelivery_max_age").Default("24h"),
		service.NewDurationField("redelivery_backoff").Default("1s"),
		service.NewDurationField("redelivery_max_backoff").Default("1m"),
		service.NewStringEnumField("redelivery_exhausted_policy", "pause", "dead_letter").Default("pause"),
	).Description("Configures how delivered Kafka records are acknowledged and committed.").Optional()
}

func franzKafkaInputConfig() *service.ConfigSpec {
	return service.NewConfigSpec().
		Stable().
		Categories("Services").
		Summary(`A Kafka input using the [Franz Kafka client library](https://github.com/twmb/franz-go).`).
		Description(`
When a consumer group is specified this input consumes one or more topics where partitions will automatically balance across any other connected clients with the same consumer group. When a consumer group is not specified topics can either be consumed in their entirety or with explicit partitions.

This input often out-performs the traditional ` + "`kafka`" + ` input as well as providing more useful logs and error messages.

### Metadata

This input adds the following metadata fields to each message:

` + "``` text" + `
- kafka_key
- kafka_topic
- kafka_partition
- kafka_offset
- kafka_timestamp_unix
- kafka_tombstone_message
- All record headers
` + "```" + `
`).
		Field(service.NewStringListField("seed_brokers").
			Description("A list of broker addresses to connect to in order to establish connections. If an item of the list contains commas it will be expanded into multiple addresses.").
			Example([]string{"localhost:9092"}).
			Example([]string{"foo:9092", "bar:9092"}).
			Example([]string{"foo:9092,bar:9092"})).
		Field(service.NewStringListField("topics").
			Description(`
A list of topics to consume from. Multiple comma separated topics can be listed in a single element. When a ` + "`consumer_group`" + ` is specified partitions are automatically distributed across consumers of a topic, otherwise all partitions are consumed.

Alternatively, it's possible to specify explicit partitions to consume from with a colon after the topic name, e.g. ` + "`foo:0`" + ` would consume the partition 0 of the topic foo. This syntax supports ranges, e.g. ` + "`foo:0-10`" + ` would consume partitions 0 through to 10 inclusive.

Finally, it's also possible to specify an explicit offset to consume from by adding another colon after the partition, e.g. ` + "`foo:0:10`" + ` would consume the partition 0 of the topic foo starting from the offset 10. If the offset is not present (or remains unspecified) then the field ` + "`start_from_oldest`" + ` determines which offset to start from.`).
			Example([]string{"foo", "bar"}).
			Example([]string{"things.*"}).
			Example([]string{"foo,bar"}).
			Example([]string{"foo:0", "bar:1", "bar:3"}).
			Example([]string{"foo:0,bar:1,bar:3"}).
			Example([]string{"foo:0-5"})).
		Field(service.NewBoolField("regexp_topics").
			Description("Whether listed topics should be interpreted as regular expression patterns for matching multiple topics. When topics are specified with explicit partitions this field must remain set to `false`.").
			Default(false)).
		Field(service.NewStringField("consumer_group").
			Description("An optional consumer group to consume as. When specified the partitions of specified topics are automatically distributed across consumers sharing a consumer group, and partition offsets are automatically committed and resumed under this name. Consumer groups are not supported when specifying explicit partitions to consume from in the `topics` field.").
			Optional()).
		Field(service.NewDurationField("session_timeout").
			Description("The maximum time a consumer group member may go without heartbeating before the broker removes it and reassigns its partitions.").
			Default("45s").Advanced()).
		Field(service.NewDurationField("heartbeat_interval").
			Description("How often a consumer group member heartbeats. This must be less than half of session_timeout.").
			Default("3s").Advanced()).
		Field(service.NewStringField("client_id").
			Description("An identifier for the client connection.").
			Default("bento").
			Advanced()).
		Field(service.NewStringField("rack_id").
			Description("A rack identifier for this client.").
			Default("").
			Advanced()).
		Field(service.NewIntField("checkpoint_limit").
			Description(`:::caution
			Setting this ` + "`checkpoint_limit: 1`" + `_will not_ enforce 'strict ordered' processing of records. Use the [kafka input processor](/docs/components/inputs/kafka/) for 'strict ordered' processing.
:::

			Determines how many messages of the same partition can be processed in parallel before applying back pressure. When a message of a given offset is delivered to the output the offset is only allowed to be committed when all messages of prior offsets have also been delivered, this ensures at-least-once delivery guarantees. However, this mechanism also increases the likelihood of duplicates in the event of crashes or server faults, reducing the checkpoint limit will mitigate this.`).
			Optional().
			Advanced()).
		Field(acknowledgmentField()).
		Field(service.NewAutoRetryNacksToggleField()).
		Field(service.NewDurationField("commit_period").
			Description("The period of time between each commit of the current partition offsets. Offsets are always committed during shutdown.").
			Default("5s").
			Advanced()).
		Field(service.NewBoolField("start_from_oldest").
			Description("Determines whether to consume from the oldest available offset, otherwise messages are consumed from the latest offset. The setting is applied when creating a new consumer group or the saved offset no longer exists.").
			Default(true).
			Advanced()).
		Field(service.NewBoolField("reconnect_on_unknown_topic_or_partition").
			Description("Determines whether to close the client and force a reconnect after seeing an UNKNOWN_TOPIC_OR_PARTITION or UNKNOWN_TOPIC_ID error.").
			Default(false).
			Version("1.8.0").
			Advanced()).
		Field(service.NewStringEnumField("auto_offset_reset", "earliest", "latest", "none").
			Description("Determines which offset to automatically consume from, matching Kafka's `auto.offset.reset` property. When specified, this takes precedence over `start_from_oldest`.").
			Version("1.6.0").
			Optional().
			Advanced()).
		Field(service.NewStringListField("group_balancers").
			Description("Balancers sets the group balancers to use for dividing topic partitions among group members. This option is equivalent to Kafka's `partition.assignment.strategies` option.").
			Version("1.3.0").
			Default([]string{"cooperative_sticky"}).
			Advanced()).
		Field(service.NewDurationField("metadata_max_age").
			Description("This sets the maximum age for the client's cached metadata, to allow detection of new topics, partitions, etc.").
			Version("1.3.0").
			Default("5m").
			Advanced()).
		Field(service.NewStringField("fetch_max_bytes").
			Description("This sets the maximum amount of bytes a broker will try to send during a fetch. Note that brokers may not obey this limit if it has records larger than this limit. Also note that this client sends a fetch to each broker concurrently, meaning the client will buffer up to `<brokers * max bytes>` worth of memory. Equivalent to Kafka's `fetch.max.bytes` option.").
			Version("1.3.0").
			Default("50MiB").
			Advanced()).
		Field(service.NewStringField("fetch_max_partition_bytes").
			Description("Sets the maximum amount of bytes that will be consumed for a single partition in a fetch request. Note that if a single batch is larger than this number, that batch will still be returned so the client can make progress. Equivalent to Kafka's `max.partition.fetch.bytes` option.").
			Version("1.3.0").
			Default("1MiB").
			Advanced()).
		Field(service.NewDurationField("fetch_max_wait").
			Description("This sets the maximum amount of time a broker will wait for a fetch response to hit the minimum number of required bytes before returning, overriding the default 5s.").
			Version("1.3.0").
			Default("5s").
			Advanced()).
		Field(service.NewIntField("preferring_lag").
			Description(`
This allows you to re-order partitions before they are fetched, given each partition's current lag.

By default, the client rotates partitions fetched by one after every fetch request. Kafka answers fetch requests in the order that partitions are requested, filling the fetch response until` + "`fetch_max_bytes`" + ` and ` + "`fetch_max_partition_bytes`" + ` are hit. All partitions eventually rotate to the front, ensuring no partition is starved.

With this option, you can return topic order and per-topic partition ordering. These orders will sort to the front (first by topic, then by partition). Any topic or partitions that you do not return are added to the end, preserving their original ordering.`).
			Version("1.3.0").
			Optional().
			Advanced()).
		Field(service.NewTLSToggledField("tls")).
		Field(saslField()).
		Field(service.NewBoolField("multi_header").Description("Decode headers into lists to allow handling of multiple values with the same key").Default(false).Advanced()).
		Field(service.NewBatchPolicyField("batching").
			Description("Allows you to configure a [batching policy](/docs/configuration/batching) that applies to individual topic partitions in order to batch messages together before flushing them for processing. Batching can be beneficial for performance as well as useful for windowed processing, and doing so this way preserves the ordering of topic partitions.").
			Advanced()).
		Field(service.NewStringField("rate_limit").
			Description("An optional [`rate_limit`](/docs/components/rate_limits/about) to throttle invocations by.").
			Default("").
			Advanced()).
		Field(service.NewBoolField("disable_auto_commit").
			Description("Deprecated proof-of-concept switch. Use acknowledgment.mode instead.").
			Default(false).
			Deprecated().
			Advanced()).
		LintRule(`
let has_topic_partitions = this.topics.any(t -> t.contains(":"))
root = if $has_topic_partitions {
  if this.consumer_group.or("") != "" {
    "this input does not support both a consumer group and explicit topic partitions"
  } else if this.regexp_topics {
    "this input does not support both regular expression topics and explicit topic partitions"
  }
}
`)
}

func init() {
	err := service.RegisterBatchInput("tyk_kafka", franzKafkaInputConfig(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.BatchInput, error) {
			rdr, err := newFranzKafkaReaderFromConfig(conf, mgr)
			if err != nil {
				return nil, err
			}
			return service.AutoRetryNacksBatchedToggled(conf, rdr)
		})
	if err != nil {
		panic(err)
	}
}

//------------------------------------------------------------------------------

type batchWithAckFn struct {
	onAck func()
	batch service.MessageBatch
}

type franzKafkaReader struct {
	seedBrokers       []string
	topics            []string
	topicPartitions   map[string]map[int32]kgo.Offset
	clientID          string
	rackID            string
	consumerGroup     string
	sessionTimeout    time.Duration
	heartbeatInterval time.Duration
	tlsConf           *tls.Config
	saslConfs         []sasl.Mechanism
	checkpointLimit   int
	autoOffsetReset   string
	commitPeriod      time.Duration
	regexPattern      bool
	multiHeader       bool
	batchPolicy       service.BatchPolicy
	acknowledgment    AcknowledgmentConfig
	ackController     *ExternalAckController
	offsetController  OffsetController
	controllerKey     ControllerKey
	maxPollRecords    int
	resetGate         sync.RWMutex
	resetting         atomic.Bool
	resetSupervisor   *RedisResetSupervisor

	reconnectOnUnknownTopic bool

	metadataMaxAge         time.Duration
	fetchMaxBytes          int32
	fetchMaxPartitionBytes int32
	fetchMaxWait           time.Duration
	preferringLagFn        kgo.PreferLagFn
	balancers              []kgo.GroupBalancer

	batchChan atomic.Value
	rateLimit string
	res       *service.Resources
	log       *service.Logger
	shutSig   *shutdown.Signaller
}

func (f *franzKafkaReader) getBatchChan() chan batchWithAckFn {
	c, _ := f.batchChan.Load().(chan batchWithAckFn)
	return c
}

func (f *franzKafkaReader) storeBatchChan(c chan batchWithAckFn) {
	f.batchChan.Store(c)
}

func (f *franzKafkaReader) waitForAccess(ctx context.Context, batch service.MessageBatch) bool {
	if f.rateLimit == "" {
		return true
	}

	if len(batch) == 0 {
		return true
	}

	for {
		var period time.Duration
		var err error
		if rerr := f.res.AccessRateLimit(ctx, f.rateLimit, func(rl service.RateLimit) {
			if mar, ok := rl.(service.MessageAwareRateLimit); ok {
				mar.Add(ctx, batch...)
			}
			period, err = rl.Access(ctx)
		}); rerr != nil {
			err = rerr
		}
		if err != nil {
			f.log.Errorf("Rate limit error: %v\n", err)
			period = time.Second
		}
		if period > 0 {
			<-time.After(period)
		} else {
			return true
		}
	}
}

func getOffsetReset(conf *service.ParsedConfig) (string, error) {
	// Allow the newer auto_offset_reset to take presedence.
	if conf.Contains("auto_offset_reset") {
		autoOffsetReset, err := conf.FieldString("auto_offset_reset")
		if err != nil {
			return "", err
		}
		return autoOffsetReset, nil
	}

	startFromOldest, err := conf.FieldBool("start_from_oldest")
	if err != nil {
		return "", err
	}

	if startFromOldest {
		return "earliest", nil
	}
	return "latest", nil
}

func parseAcknowledgmentConfig(conf *service.ParsedConfig) (AcknowledgmentConfig, error) {
	ack := defaultAcknowledgmentConfig()
	if !conf.Contains("acknowledgment") {
		return ack, nil
	}

	c := conf.Namespace("acknowledgment")
	var err error
	if ack.Mode, err = c.FieldString("mode"); err != nil {
		return ack, err
	}
	if ack.CheckpointLimit, err = c.FieldInt("checkpoint_limit"); err != nil {
		return ack, err
	}
	if ack.MaxInFlight, err = c.FieldInt("max_in_flight"); err != nil {
		return ack, err
	}
	maxBytes, err := c.FieldString("max_in_flight_bytes")
	if err != nil {
		return ack, err
	}
	if ack.MaxInFlightBytes, err = humanize.ParseBytes(maxBytes); err != nil {
		return ack, fmt.Errorf("invalid acknowledgment.max_in_flight_bytes: %w", err)
	}
	if ack.AckDeadline, err = c.FieldDuration("ack_deadline"); err != nil {
		return ack, err
	}
	if ack.MissingAckPolicy, err = c.FieldString("missing_ack_policy"); err != nil {
		return ack, err
	}
	if ack.TokenTTL, err = c.FieldDuration("token_ttl"); err != nil {
		return ack, err
	}
	if ack.Routing, err = c.FieldString("routing"); err != nil {
		return ack, err
	}
	if ack.ComponentID, err = c.FieldString("component_id"); err != nil {
		return ack, err
	}
	if ack.CommitInterval, err = c.FieldDuration("commit_interval"); err != nil {
		return ack, err
	}
	if ack.CommitBatchSize, err = c.FieldInt("commit_batch_size"); err != nil {
		return ack, err
	}
	if ack.DeadLetterTopic, err = c.FieldString("dead_letter_topic"); err != nil {
		return ack, err
	}
	if ack.RedeliveryMaxAttempts, err = c.FieldInt("redelivery_max_attempts"); err != nil {
		return ack, err
	}
	if ack.RedeliveryMaxAge, err = c.FieldDuration("redelivery_max_age"); err != nil {
		return ack, err
	}
	if ack.RedeliveryBackoff, err = c.FieldDuration("redelivery_backoff"); err != nil {
		return ack, err
	}
	if ack.RedeliveryMaxBackoff, err = c.FieldDuration("redelivery_max_backoff"); err != nil {
		return ack, err
	}
	if ack.RedeliveryExhaustedPolicy, err = c.FieldString("redelivery_exhausted_policy"); err != nil {
		return ack, err
	}

	if ack.CheckpointLimit <= 0 {
		return ack, errors.New("acknowledgment.checkpoint_limit must be greater than zero")
	}
	if ack.MaxInFlight <= 0 {
		return ack, errors.New("acknowledgment.max_in_flight must be greater than zero")
	}
	if ack.MaxInFlightBytes == 0 {
		return ack, errors.New("acknowledgment.max_in_flight_bytes must be greater than zero")
	}
	if ack.AckDeadline <= 0 {
		return ack, errors.New("acknowledgment.ack_deadline must be greater than zero")
	}
	if ack.TokenTTL <= 0 {
		return ack, errors.New("acknowledgment.token_ttl must be greater than zero")
	}
	if ack.TokenTTL < ack.AckDeadline {
		return ack, errors.New("acknowledgment.token_ttl must be greater than or equal to acknowledgment.ack_deadline")
	}
	if ack.CommitInterval <= 0 {
		return ack, errors.New("acknowledgment.commit_interval must be greater than zero")
	}
	if ack.CommitBatchSize <= 0 {
		return ack, errors.New("acknowledgment.commit_batch_size must be greater than zero")
	}
	if ack.MissingAckPolicy == "dead_letter" && strings.TrimSpace(ack.DeadLetterTopic) == "" {
		return ack, errors.New("acknowledgment.dead_letter_topic is required for dead_letter policy")
	}
	if ack.RedeliveryMaxAttempts <= 0 || ack.RedeliveryMaxAge <= 0 || ack.RedeliveryBackoff <= 0 || ack.RedeliveryMaxBackoff < ack.RedeliveryBackoff {
		return ack, errors.New("acknowledgment redelivery limits and backoff must be positive and max_backoff must be at least backoff")
	}
	if ack.MissingAckPolicy == "redeliver" && ack.RedeliveryExhaustedPolicy == "dead_letter" && strings.TrimSpace(ack.DeadLetterTopic) == "" {
		return ack, errors.New("acknowledgment.dead_letter_topic is required for dead_letter exhaustion policy")
	}
	return ack, nil
}

func newFranzKafkaReaderFromConfig(conf *service.ParsedConfig, res *service.Resources) (*franzKafkaReader, error) {
	f := franzKafkaReader{
		res:     res,
		log:     res.Logger(),
		shutSig: shutdown.NewSignaller(),
	}

	brokerList, err := conf.FieldStringList("seed_brokers")
	if err != nil {
		return nil, err
	}
	for _, b := range brokerList {
		f.seedBrokers = append(f.seedBrokers, strings.Split(b, ",")...)
	}

	if slices.Contains(f.seedBrokers, "") {
		return nil, errInvalidSeedBrokerValue
	}

	if len(f.seedBrokers) == 0 {
		return nil, errInvalidSeedBrokerCount
	}

	if f.autoOffsetReset, err = getOffsetReset(conf); err != nil {
		return nil, err
	}

	topicList, err := conf.FieldStringList("topics")
	if err != nil {
		return nil, err
	}

	var defaultOffset int64 = -1
	switch f.autoOffsetReset {
	case "none", "latest":
		defaultOffset = -1 // start from newest offset
	case "earliest":
		defaultOffset = -2 // start from oldest available offset
	}

	var topicPartitions map[string]map[int32]int64
	if f.topics, topicPartitions, err = parseTopics(topicList, defaultOffset, true); err != nil {
		return nil, err
	}
	if len(topicPartitions) > 0 {
		f.topicPartitions = map[string]map[int32]kgo.Offset{}
		for topic, partitions := range topicPartitions {
			partMap := map[int32]kgo.Offset{}
			for part, offset := range partitions {
				partMap[part] = kgo.NewOffset().At(offset)
			}
			f.topicPartitions[topic] = partMap
		}
	}

	if f.regexPattern, err = conf.FieldBool("regexp_topics"); err != nil {
		return nil, err
	}

	if f.clientID, err = conf.FieldString("client_id"); err != nil {
		return nil, err
	}

	if f.rackID, err = conf.FieldString("rack_id"); err != nil {
		return nil, err
	}

	if conf.Contains("consumer_group") {
		if f.consumerGroup, err = conf.FieldString("consumer_group"); err != nil {
			return nil, err
		}
	}
	if f.sessionTimeout, err = conf.FieldDuration("session_timeout"); err != nil {
		return nil, err
	}
	if f.heartbeatInterval, err = conf.FieldDuration("heartbeat_interval"); err != nil {
		return nil, err
	}
	if f.sessionTimeout <= 0 {
		return nil, errors.New("session_timeout must be positive")
	}
	if f.heartbeatInterval <= 0 {
		return nil, errors.New("heartbeat_interval must be positive")
	}
	if f.sessionTimeout < 2*f.heartbeatInterval {
		return nil, errors.New("session_timeout must be at least twice heartbeat_interval")
	}

	if f.reconnectOnUnknownTopic, err = conf.FieldBool("reconnect_on_unknown_topic_or_partition"); err != nil {
		return nil, err
	}

	if f.acknowledgment, err = parseAcknowledgmentConfig(conf); err != nil {
		return nil, err
	}
	if f.acknowledgment.Mode == AcknowledgmentModeExternal {
		if f.consumerGroup == "" {
			return nil, errors.New("acknowledgment.mode external_ack requires consumer_group")
		}
		if len(f.topicPartitions) > 0 {
			return nil, errors.New("acknowledgment.mode external_ack is incompatible with explicit topic partitions")
		}
		if conf.Contains("checkpoint_limit") {
			return nil, errors.New("top-level checkpoint_limit cannot be combined with acknowledgment.mode external_ack")
		}
		f.checkpointLimit = f.acknowledgment.CheckpointLimit
	} else if conf.Contains("checkpoint_limit") {
		if f.checkpointLimit, err = conf.FieldInt("checkpoint_limit"); err != nil {
			return nil, err
		}
	} else {
		f.checkpointLimit = 1024
	}

	if f.commitPeriod, err = conf.FieldDuration("commit_period"); err != nil {
		return nil, err
	}

	if f.metadataMaxAge, err = conf.FieldDuration("metadata_max_age"); err != nil {
		return nil, err
	}

	fetchMaxBytesStr, err := conf.FieldString("fetch_max_bytes")
	if err != nil {
		return nil, err
	}

	fetchMaxBytes, err := humanize.ParseBytes(fetchMaxBytesStr)
	if err != nil {
		return nil, err
	}
	f.fetchMaxBytes = int32(fetchMaxBytes)

	fetchMaxPartitionBytesStr, err := conf.FieldString("fetch_max_partition_bytes")
	if err != nil {
		return nil, err
	}

	fetchMaxPartitionBytes, err := humanize.ParseBytes(fetchMaxPartitionBytesStr)
	if err != nil {
		return nil, err
	}
	f.fetchMaxPartitionBytes = int32(fetchMaxPartitionBytes)

	if f.fetchMaxWait, err = conf.FieldDuration("fetch_max_wait"); err != nil {
		return nil, err
	}

	if conf.Contains("preferring_lag") {
		if preferringLag, err := conf.FieldInt("preferring_lag"); err != nil {
			return nil, err
		} else if preferringLag > 0 {
			f.preferringLagFn = kgo.PreferLagAt(int64(preferringLag))
		}
	}

	var balancers []string
	if balancers, err = conf.FieldStringList("group_balancers"); err != nil {
		return nil, err
	}

	if len(balancers) > 0 {
		seen := make(map[string]struct{})
		for _, b := range balancers {
			if _, ok := seen[b]; ok {
				res.Logger().Warnf("Skipping duplicate group_balancer field %s", b)
				continue
			}
			seen[b] = struct{}{}

			switch b {
			case "round_robin":
				f.balancers = append(f.balancers, kgo.RoundRobinBalancer())
			case "range":
				f.balancers = append(f.balancers, kgo.RangeBalancer())
			case "sticky":
				f.balancers = append(f.balancers, kgo.StickyBalancer())
			case "cooperative_sticky":
				f.balancers = append(f.balancers, kgo.CooperativeStickyBalancer())
			default:
				return nil, fmt.Errorf("undefined group_balancer option: [%s]", b)
			}
		}
	}

	if f.batchPolicy, err = conf.FieldBatchPolicy("batching"); err != nil {
		return nil, err
	}

	if f.rateLimit, err = conf.FieldString("rate_limit"); err != nil {
		return nil, err
	}

	disableAutoCommit, err := conf.FieldBool("disable_auto_commit")
	if err != nil {
		return nil, err
	}
	if disableAutoCommit && f.acknowledgment.Mode != AcknowledgmentModeExternal {
		return nil, errors.New("disable_auto_commit is deprecated; configure acknowledgment.mode: external_ack")
	}

	tlsConf, tlsEnabled, err := conf.FieldTLSToggled("tls")
	if err != nil {
		return nil, err
	}
	if tlsEnabled {
		f.tlsConf = tlsConf
	}
	if f.multiHeader, err = conf.FieldBool("multi_header"); err != nil {
		return nil, err
	}
	if f.saslConfs, err = saslMechanismsFromConfig(conf); err != nil {
		return nil, err
	}

	return &f, nil
}

type msgWithRecord struct {
	msg *service.Message
	r   *kgo.Record
}

func (f *franzKafkaReader) recordToMessage(record *kgo.Record) (*msgWithRecord, error) {
	msg := service.NewMessage(record.Value)
	msg.MetaSetMut("kafka_key", string(record.Key))
	msg.MetaSetMut("kafka_topic", record.Topic)
	msg.MetaSetMut("kafka_partition", int(record.Partition))
	msg.MetaSetMut("kafka_offset", int(record.Offset))
	msg.MetaSetMut("kafka_timestamp_unix", record.Timestamp.Unix())
	msg.MetaSetMut("kafka_tombstone_message", record.Value == nil)
	if f.multiHeader {
		// in multi header mode we gather headers so we can encode them as lists
		headers := map[string][]any{}

		for _, hdr := range record.Headers {
			headers[hdr.Key] = append(headers[hdr.Key], string(hdr.Value))
		}

		for key, values := range headers {
			msg.MetaSetMut(key, values)
		}
	} else {
		for _, hdr := range record.Headers {
			msg.MetaSetMut(hdr.Key, string(hdr.Value))
		}
	}

	if f.ackController != nil {
		if err := f.ackController.Track(record, msg); err != nil {
			return nil, err
		}
	}

	// The acknowledgement controller has retained a bounded copy when needed.
	// The checkpoint record itself no longer needs the potentially large body.
	record.Key = nil
	record.Value = nil

	return &msgWithRecord{
		msg: msg,
		r:   record,
	}, nil
}

//------------------------------------------------------------------------------

type partitionTracker struct {
	batcherLock    sync.Mutex
	topBatchRecord *kgo.Record
	batcher        *service.Batcher

	checkpointerLock sync.Mutex
	checkpointer     *checkpoint.Uncapped[*kgo.Record]

	outBatchChan chan<- batchWithAckFn
	commitFn     func(r *kgo.Record)

	shutSig *shutdown.Signaller
}

func newPartitionTracker(batcher *service.Batcher, batchChan chan<- batchWithAckFn, commitFn func(r *kgo.Record)) *partitionTracker {
	pt := &partitionTracker{
		batcher:      batcher,
		checkpointer: checkpoint.NewUncapped[*kgo.Record](),
		outBatchChan: batchChan,
		commitFn:     commitFn,
		shutSig:      shutdown.NewSignaller(),
	}
	go pt.loop()
	return pt
}

func (p *partitionTracker) loop() {
	defer func() {
		if p.batcher != nil {
			p.batcher.Close(context.Background())
		}
		p.shutSig.TriggerHasStopped()
	}()

	// No need to loop when there's no batcher for async writes.
	if p.batcher == nil {
		return
	}

	var flushBatch <-chan time.Time
	var flushBatchTicker *time.Ticker
	adjustTimedFlush := func() {
		if flushBatch != nil || p.batcher == nil {
			return
		}

		tNext, exists := p.batcher.UntilNext()
		if !exists {
			if flushBatchTicker != nil {
				flushBatchTicker.Stop()
				flushBatchTicker = nil
			}
			return
		}

		if flushBatchTicker != nil {
			flushBatchTicker.Reset(tNext)
		} else {
			flushBatchTicker = time.NewTicker(tNext)
		}
		flushBatch = flushBatchTicker.C
	}

	closeAtLeisureCtx, done := p.shutSig.SoftStopCtx(context.Background())
	defer done()

	for {
		adjustTimedFlush()
		select {
		case <-flushBatch:
			var sendBatch service.MessageBatch
			var sendRecord *kgo.Record

			// Wrap this in a closure to make locking/unlocking easier.
			func() {
				p.batcherLock.Lock()
				defer p.batcherLock.Unlock()

				flushBatch = nil
				if tNext, exists := p.batcher.UntilNext(); !exists || tNext > 1 {
					// This can happen if a pushed message triggered a batch before
					// the last known flush period. In this case we simply enter the
					// loop again which readjusts our flush batch timer.
					return
				}

				if sendBatch, _ = p.batcher.Flush(closeAtLeisureCtx); len(sendBatch) == 0 {
					return
				}
				sendRecord = p.topBatchRecord
				p.topBatchRecord = nil
			}()

			if len(sendBatch) > 0 {
				if err := p.sendBatch(closeAtLeisureCtx, sendBatch, sendRecord); err != nil {
					return
				}
			}
		case <-p.shutSig.SoftStopChan():
			return
		}
	}
}

func (p *partitionTracker) sendBatch(ctx context.Context, b service.MessageBatch, r *kgo.Record) error {
	p.checkpointerLock.Lock()
	releaseFn := p.checkpointer.Track(r, int64(len(b)))
	p.checkpointerLock.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.outBatchChan <- batchWithAckFn{
		batch: b,
		onAck: func() {
			p.checkpointerLock.Lock()
			releaseRecord := releaseFn()
			p.checkpointerLock.Unlock()

			if releaseRecord != nil && *releaseRecord != nil {
				p.commitFn(*releaseRecord)
			}
		},
	}:
	}
	return nil
}

func (p *partitionTracker) add(ctx context.Context, m *msgWithRecord, limit int) (sendBatch service.MessageBatch, pauseFetch bool) {
	if p.batcher != nil {
		// Wrap this in a closure to make locking/unlocking easier.
		func() {
			p.batcherLock.Lock()
			defer p.batcherLock.Unlock()

			if p.batcher.Add(m.msg) {
				// Batch triggered, we flush it here synchronously.
				sendBatch, _ = p.batcher.Flush(ctx)
			} else {
				// Otherwise store the latest record as the representative of the
				// pending batch offset. This will be used by the timer based
				// flushing mechanism within loop() if applicable.
				p.topBatchRecord = m.r
			}
		}()
	} else {
		sendBatch = service.MessageBatch{m.msg}
	}

	if len(sendBatch) > 0 {
		// Ignoring in the error here is fine, it implies shut down has been
		// triggered and we would only acknowledge the message by committing it
		// if it were successfully delivered.
		_ = p.sendBatch(ctx, sendBatch, m.r)
	}

	p.checkpointerLock.Lock()
	pauseFetch = p.checkpointer.Pending() >= int64(limit)
	p.checkpointerLock.Unlock()
	return
}

func (p *partitionTracker) pauseFetch(limit int) (pauseFetch bool) {
	p.checkpointerLock.Lock()
	pauseFetch = p.checkpointer.Pending() >= int64(limit)
	p.checkpointerLock.Unlock()
	return
}

func (p *partitionTracker) close(ctx context.Context) error {
	p.shutSig.TriggerSoftStop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.shutSig.HasStoppedChan():
	}
	return nil
}

//------------------------------------------------------------------------------

type checkpointTracker struct {
	mut    sync.Mutex
	topics map[string]map[int32]*partitionTracker

	res       *service.Resources
	batchChan chan<- batchWithAckFn
	commitFn  func(r *kgo.Record)
	batchPol  service.BatchPolicy
}

func newCheckpointTracker(
	res *service.Resources,
	batchChan chan<- batchWithAckFn,
	releaseFn func(r *kgo.Record),
	batchPol service.BatchPolicy,
) *checkpointTracker {
	return &checkpointTracker{
		topics:    map[string]map[int32]*partitionTracker{},
		res:       res,
		batchChan: batchChan,
		commitFn:  releaseFn,
		batchPol:  batchPol,
	}
}

func (c *checkpointTracker) close() {
	c.mut.Lock()
	defer c.mut.Unlock()

	for _, partitions := range c.topics {
		for _, tracker := range partitions {
			_ = tracker.close(context.Background())
		}
	}
}

func (c *checkpointTracker) addRecord(ctx context.Context, m *msgWithRecord, limit int) (sendBatch service.MessageBatch, pauseFetch bool) {
	c.mut.Lock()
	defer c.mut.Unlock()

	topicTracker := c.topics[m.r.Topic]
	if topicTracker == nil {
		topicTracker = map[int32]*partitionTracker{}
		c.topics[m.r.Topic] = topicTracker
	}

	partTracker := topicTracker[m.r.Partition]
	if partTracker == nil {
		var batcher *service.Batcher
		if !c.batchPol.IsNoop() {
			var err error
			if batcher, err = c.batchPol.NewBatcher(c.res); err != nil {
				c.res.Logger().Errorf("Failed to initialise batch policy: %v, falling back to individual message delivery", err)
				batcher = nil
			}
		}
		partTracker = newPartitionTracker(batcher, c.batchChan, c.commitFn)
		topicTracker[m.r.Partition] = partTracker
	}

	return partTracker.add(ctx, m, limit)
}

func (c *checkpointTracker) pauseFetch(topic string, partition int32, limit int) bool {
	c.mut.Lock()
	defer c.mut.Unlock()

	topicTracker := c.topics[topic]
	if topicTracker == nil {
		return false
	}
	partTracker := topicTracker[partition]
	if partTracker == nil {
		return false
	}

	return partTracker.pauseFetch(limit)
}

func (c *checkpointTracker) removeTopicPartitions(ctx context.Context, m map[string][]int32) {
	c.mut.Lock()
	defer c.mut.Unlock()

	for topicName, lostTopic := range m {
		trackedTopic, exists := c.topics[topicName]
		if !exists {
			continue
		}
		for _, lostPartition := range lostTopic {
			if trackedPartition, exists := trackedTopic[lostPartition]; exists {
				_ = trackedPartition.close(ctx)
			}
			delete(trackedTopic, lostPartition)
		}
		if len(trackedTopic) == 0 {
			delete(c.topics, topicName)
		}
	}
}

// If this returns false, the reader will close the client to force a reconnect.
func (f *franzKafkaReader) isRetriableError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}

	// Currently, franzgo consumers cannot deal with recreated topics.
	// Issue: https://github.com/twmb/franz-go/issues/676.
	// Since the metadata won't refresh topic IDs that have been deleted, the consumer will keep failing forever.
	// The temporary solution here is to add a flag `reconnect_on_unknown_topic_or_partition`
	// so that if it's set and an unknown topic error is received, Bento forces a reconnect
	// so that it can pick up the newly created topic.
	isUnknownTopicErr := err == kerr.UnknownTopicOrPartition || err == kerr.UnknownTopicID
	if isUnknownTopicErr && f.reconnectOnUnknownTopic {
		return false
	}
	return kerr.IsRetriable(err)
}

//------------------------------------------------------------------------------

func (f *franzKafkaReader) Connect(ctx context.Context) error {
	if f.getBatchChan() != nil {
		return nil
	}
	if f.shutSig.IsSoftStopSignalled() {
		f.shutSig.TriggerHasStopped()
		return service.ErrEndOfInput
	}

	var initialOffset kgo.Offset
	switch f.autoOffsetReset {
	case "earliest":
		initialOffset = kgo.NewOffset().AtStart()
	case "latest":
		initialOffset = kgo.NewOffset().AtEnd()
	case "none":
		initialOffset = kgo.NewOffset().AtCommitted()
	}

	batchChan := make(chan batchWithAckFn)
	var acknowledgmentHandler AcknowledgmentController
	var distributedOwner *DistributedAckOwner

	if f.acknowledgment.Mode == AcknowledgmentModeExternal {
		if f.acknowledgment.ComponentID == "" {
			return errors.New("acknowledgment.component_id is required for external_ack")
		}
		f.controllerKey = ControllerKey{APIID: "runtime", StreamID: "runtime", ComponentID: f.acknowledgment.ComponentID}
		codec, err := GlobalRuntimeAckKeyRegistry.Resolve(ctx, f.acknowledgment.ComponentID, controllerScope(f.controllerKey))
		if err != nil {
			return fmt.Errorf("resolve acknowledgment signing keys: %w", err)
		}
		replayID, err := randomIdentity()
		if err != nil {
			return fmt.Errorf("create replay identity: %w", err)
		}
		f.ackController, err = NewExternalAckController(f.controllerKey, strings.Join(f.seedBrokers, ","), replayID, codec, f.acknowledgment)
		if err != nil {
			return err
		}
		deliveryOwner, identityErr := randomIdentity()
		if identityErr != nil {
			f.ackController.Close()
			f.ackController = nil
			return fmt.Errorf("create acknowledgement owner identity: %w", identityErr)
		}
		f.ackController.SetDeliveryAuthority(f.consumerGroup, deliveryOwner)
		acknowledgmentHandler = f.ackController
		if f.acknowledgment.Routing == "distributed" {
			transport, resolveErr := GlobalRuntimeAckTransportRegistry.Resolve(ctx, f.acknowledgment.ComponentID)
			if resolveErr != nil {
				f.ackController.Close()
				f.ackController = nil
				return fmt.Errorf("resolve distributed acknowledgment transport: %w", resolveErr)
			}
			router, routerErr := NewPartitionedDurableAcknowledgmentRouter(f.controllerKey, transport, codec)
			if routerErr != nil {
				f.ackController.Close()
				f.ackController = nil
				return fmt.Errorf("create distributed acknowledgment router: %w", routerErr)
			}
			distributedOwner, err = NewDistributedAckOwner(transport, f.controllerKey, deliveryOwner, f.ackController)
			if err != nil {
				f.ackController.Close()
				f.ackController = nil
				return err
			}
			acknowledgmentHandler = router
		}
	}

	var cl *kgo.Client
	commitFn := func(r *kgo.Record) {}
	if f.consumerGroup != "" && f.acknowledgment.Mode == AcknowledgmentModeOutput {
		commitFn = func(r *kgo.Record) {
			if cl == nil {
				return
			}
			cl.MarkCommitRecords(r)
		}
	}
	checkpoints := newCheckpointTracker(f.res, batchChan, commitFn, f.batchPolicy)

	clientOpts := []kgo.Opt{
		kgo.SeedBrokers(f.seedBrokers...),
		kgo.ConsumeTopics(f.topics...),
		kgo.ConsumePartitions(f.topicPartitions),
		kgo.ConsumeResetOffset(initialOffset),
		kgo.SASL(f.saslConfs...),
		kgo.ConsumerGroup(f.consumerGroup),
		kgo.ClientID(f.clientID),
		kgo.Rack(f.rackID),

		kgo.MetadataMaxAge(f.metadataMaxAge),
		kgo.FetchMaxBytes(f.fetchMaxBytes),
		kgo.FetchMaxPartitionBytes(f.fetchMaxPartitionBytes),
		kgo.FetchMaxWait(f.fetchMaxWait),
		kgo.ConsumePreferringLagFn(f.preferringLagFn),
		kgo.Balancers(f.balancers...),
	}
	if f.reconnectOnUnknownTopic {
		clientOpts = append(clientOpts, kgo.KeepRetryableFetchErrors())
	}

	var assignedPartitions assignmentState
	var ownershipPending assignmentState
	if f.consumerGroup != "" {
		cgOpts := []kgo.Opt{
			kgo.SessionTimeout(f.sessionTimeout),
			kgo.HeartbeatInterval(f.heartbeatInterval),
			kgo.OnPartitionsAssigned(func(assignCtx context.Context, client *kgo.Client, m map[string][]int32) {
				refreshIdentity := func(metadataCtx context.Context) error {
					if f.ackController == nil {
						return nil
					}
					topics := make([]string, 0, len(m))
					for topic := range m {
						topics = append(topics, topic)
					}
					slices.Sort(topics)
					metadata, metadataErr := kadm.NewClient(client).Metadata(metadataCtx, topics...)
					if metadataErr != nil {
						return fmt.Errorf("refresh Kafka identity: %w", metadataErr)
					}
					topicIDs := make(map[string]string, len(metadata.Topics))
					for topic, detail := range metadata.Topics {
						if detail.Err == nil {
							topicIDs[topic] = detail.ID.String()
						}
					}
					f.ackController.SetKafkaIdentity(metadata.Cluster, topicIDs)
					return nil
				}
				assignedPartitions.add(m)
				if distributedOwner != nil {
					ownershipPending.add(m)
					client.PauseFetchPartitions(m)
					memberID, generation := client.GroupMetadata()
					identity := KafkaGroupIdentity{Generation: generation, MemberID: memberID}
					distributedOwner.AssignEventually(m, identity, refreshIdentity, func(ready map[string][]int32) {
						if f.ackController != nil {
							f.ackController.AssignPartitions(ready)
						}
						ownershipPending.remove(ready)
					}, func(assignErr error) {
						f.log.Errorf("Distributed acknowledgment ownership was fenced: %v", assignErr)
						go client.Close()
					})
				} else if identityErr := refreshIdentity(assignCtx); identityErr != nil {
					f.log.Errorf("Kafka identity refresh failed: %v", identityErr)
					go client.Close()
				} else if f.ackController != nil {
					f.ackController.AssignPartitions(m)
				}
			}),
			kgo.OnPartitionsRevoked(func(rctx context.Context, c *kgo.Client, m map[string][]int32) {
				defer assignedPartitions.remove(m)
				ownershipPending.remove(m)
				if distributedOwner != nil {
					distributedOwner.Revoke(m)
				}
				if f.acknowledgment.Mode == AcknowledgmentModeOutput {
					if commitErr := c.CommitMarkedOffsets(rctx); commitErr != nil {
						f.log.Errorf("Commit error on partition revoke: %v", commitErr)
					}
				} else if f.ackController != nil {
					if commitErr := f.ackController.RevokePartitions(rctx, m); commitErr != nil {
						f.log.Errorf("External acknowledgment revocation barrier failed: %v", commitErr)
					}
				}
				checkpoints.removeTopicPartitions(rctx, m)
			}),
			kgo.OnPartitionsLost(func(rctx context.Context, _ *kgo.Client, m map[string][]int32) {
				defer assignedPartitions.remove(m)
				ownershipPending.remove(m)
				if distributedOwner != nil {
					distributedOwner.Revoke(m)
				}
				// No point trying to commit our offsets, just clean up our topic map
				if f.ackController != nil {
					f.ackController.LosePartitions(m)
				}
				checkpoints.removeTopicPartitions(rctx, m)
			}),
			kgo.WithLogger(&kgoLogger{f.log}),
		}

		cgOpts = append(cgOpts, acknowledgmentGroupCommitOptions(f.acknowledgment.Mode, f.commitPeriod)...)
		clientOpts = append(clientOpts, cgOpts...)
	}

	if f.tlsConf != nil {

		clientOpts = append(clientOpts, kgo.DialTLSConfig(f.tlsConf))
	}

	if f.regexPattern {
		clientOpts = append(clientOpts, kgo.ConsumeRegex())
	}
	if f.acknowledgment.Mode == AcknowledgmentModeExternal {
		// Admission is evaluated after Kafka reveals a record's partition and
		// encoded size. Polling one at a time ensures a fetch cannot overrun a
		// partition window or the global record bound before pause takes effect.
		f.maxPollRecords = 1
		clientOpts = append(clientOpts, kgo.MaxConcurrentFetches(1))
		if byteLimit := int64(f.acknowledgment.MaxInFlightBytes); byteLimit > 0 {
			if byteLimit < int64(f.fetchMaxBytes) {
				clientOpts = append(clientOpts, kgo.FetchMaxBytes(int32(byteLimit)))
			}
			if byteLimit < int64(f.fetchMaxPartitionBytes) {
				clientOpts = append(clientOpts, kgo.FetchMaxPartitionBytes(int32(byteLimit)))
			}
		}
	}

	var err error
	if cl, err = kgo.NewClient(clientOpts...); err != nil {
		if distributedOwner != nil {
			distributedOwner.Close()
		}
		if f.ackController != nil {
			f.ackController.Close()
			f.ackController = nil
		}
		return err
	}
	var controllerRegistration *ControllerRegistration
	var resetStore ResetStateStore
	if f.ackController != nil {
		metadataClient := kadm.NewClient(cl)
		var metadata kadm.Metadata
		if f.regexPattern {
			metadata, err = metadataClient.Metadata(ctx)
		} else {
			metadata, err = metadataClient.Metadata(ctx, f.topics...)
		}
		if err != nil {
			if distributedOwner != nil {
				distributedOwner.Close()
			}
			cl.Close()
			f.ackController.Close()
			f.ackController = nil
			return fmt.Errorf("resolve Kafka cluster/topic identity: %w", err)
		}
		topicIDs := make(map[string]string, len(metadata.Topics))
		for topic, detail := range metadata.Topics {
			if detail.Err == nil {
				topicIDs[topic] = detail.ID.String()
			}
		}
		f.ackController.SetKafkaIdentity(metadata.Cluster, topicIDs)
		f.ackController.SetCommitter(cl)
		if f.acknowledgment.MissingAckPolicy == "dead_letter" {
			f.ackController.SetDeadLetterWriter(NewKafkaDeadLetterWriter(cl, f.acknowledgment.DeadLetterTopic))
		}
		admin, resetErr := NewKadmOffsetResetAdmin(cl)
		if resetErr == nil {
			if f.acknowledgment.Routing == "distributed" {
				resetStore, resetErr = GlobalRuntimeResetStateStoreRegistry.Resolve(ctx, f.acknowledgment.ComponentID)
			}
			var localReset *LocalOffsetResetController
			if resetErr == nil {
				var coordinator ResetExecutionCoordinator
				if redisStore, ok := resetStore.(*RedisResetStateStore); ok {
					if f.resetSupervisor == nil {
						participantID, identityErr := randomIdentity()
						if identityErr != nil {
							resetErr = identityErr
						} else {
							f.resetSupervisor, resetErr = NewRedisResetSupervisor(redisStore, f.consumerGroup, participantID, &f.resetGate, &f.resetting)
						}
					}
					if resetErr == nil {
						f.resetSupervisor.UpdateClient(cl, f.ackController)
						coordinator = f.resetSupervisor
					}
				}
				if resetErr == nil {
					var auditor DurableResetAuditSink
					if candidate, ok := resetStore.(DurableResetAuditSink); ok {
						auditor = candidate
					}
					localReset, resetErr = NewLocalOffsetResetController(LocalOffsetResetControllerConfig{ConsumerGroup: f.consumerGroup, Topics: f.topics, Admin: admin, Store: resetStore, AllowActivePlan: true, Coordinator: coordinator, Auditor: auditor, AuditKey: f.controllerKey, RequireAudit: f.acknowledgment.Routing == "distributed"})
				}
			}
			if resetErr == nil {
				f.offsetController, resetErr = NewConnectorOffsetController(localReset, admin, f.consumerGroup, cl, &f.resetGate, &f.resetting, f.ackController)
				if resetErr == nil && f.resetSupervisor != nil {
					f.offsetController.(*ConnectorOffsetController).EnableDistributedCoordination()
				}
			}
		}
		if resetErr != nil {
			if distributedOwner != nil {
				distributedOwner.Close()
			}
			cl.Close()
			f.ackController.Close()
			f.ackController = nil
			return fmt.Errorf("create offset reset controller: %w", resetErr)
		}
		controllerRegistration, err = GlobalControllerRegistry.Register(f.controllerKey, Controllers{Acknowledgments: acknowledgmentHandler, Offsets: f.offsetController, Status: f.ackController})
		if err != nil {
			if distributedOwner != nil {
				distributedOwner.Close()
			}
			cl.Close()
			f.ackController.Close()
			f.ackController = nil
			f.offsetController = nil
			return fmt.Errorf("register acknowledgment controller: %w", err)
		}
	}

	go func() {
		defer func() {
			if f.resetSupervisor != nil {
				f.resetSupervisor.UpdateClient(nil, nil)
			}
			if distributedOwner != nil {
				distributedOwner.Close()
			}
			if controllerRegistration != nil {
				controllerRegistration.Unregister()
			}
			if f.ackController != nil {
				f.ackController.Close()
				f.ackController = nil
			}
			cl.Close()
			checkpoints.close()
			f.storeBatchChan(nil)
			close(batchChan)
			if f.shutSig.IsSoftStopSignalled() {
				f.shutSig.TriggerHasStopped()
			}
		}()

		closeCtx, done := f.shutSig.SoftStopCtx(context.Background())
		defer done()
		var capacityPaused map[string][]int32
		admissionBlocked := map[string][]int32{}
		var pendingFetched *kgo.Record

		for {
			if f.ackController != nil {
				if pendingFetched != nil && f.ackController.CanTrack(pendingFetched) {
					message, messageErr := f.recordToMessage(pendingFetched)
					if messageErr == nil {
						batch, _ := checkpoints.addRecord(closeCtx, message, f.checkpointLimit)
						f.waitForAccess(ctx, batch)
						pendingFetched = nil
					}
				}
				if (pendingFetched != nil || !f.ackController.HasCapacity()) && capacityPaused == nil {
					assigned := assignedPartitions.snapshot()
					previouslyPaused := cl.PauseFetchPartitions(assigned)
					capacityPaused = partitionDifference(assigned, previouslyPaused)
				} else if pendingFetched == nil && f.ackController.HasCapacity() && capacityPaused != nil {
					// Resume is centralized in the reconciliation below so ownership,
					// checkpoint, deadline, and admission gates are all observed.
					capacityPaused = nil
				}
			}
			// Using a stall prevention context here because I've realised we
			// might end up disabling literally all the partitions and topics
			// we're allocated.
			//
			// In this case we don't want to actually resume any of them yet so
			// I add a forced timeout to deal with it.
			stallCtx, pollDone := context.WithTimeout(closeCtx, time.Second)
			var fetches kgo.Fetches
			f.resetGate.RLock()
			if f.maxPollRecords > 0 {
				fetches = cl.PollRecords(stallCtx, f.maxPollRecords)
			} else {
				fetches = cl.PollFetches(stallCtx)
			}
			f.resetGate.RUnlock()
			pollDone()

			if errs := fetches.Errors(); len(errs) > 0 {
				// Any non-temporal error sets this true and we close the client
				// forcing a reconnect.
				nonTemporalErr := false

				for _, err := range errs {
					if f.isRetriableError(err.Err) {
						continue
					}

					nonTemporalErr = true

					if !errors.Is(err.Err, kgo.ErrClientClosed) {
						f.log.Errorf("Kafka poll error on topic %v, partition %v: %v", err.Topic, err.Partition, err.Err)
					}
				}

				if nonTemporalErr {
					cl.Close()
					return
				}
			}
			if closeCtx.Err() != nil {
				return
			}

			pauseTopicPartitions := clonePartitionMap(admissionBlocked)
			for topic, partitions := range capacityPaused {
				pauseTopicPartitions[topic] = append(pauseTopicPartitions[topic], partitions...)
			}
			ownershipBlocked := ownershipPending.snapshot()
			for topic, partitions := range ownershipBlocked {
				pauseTopicPartitions[topic] = append(pauseTopicPartitions[topic], partitions...)
			}
			iter := fetches.RecordIter()
			for !iter.Done() {
				record := iter.Next()
				message, messageErr := f.recordToMessage(record)
				if messageErr != nil {
					f.log.Errorf("Kafka external acknowledgement tracking failed for topic %v partition %v offset %v: %v", record.Topic, record.Partition, record.Offset, messageErr)
					if errors.Is(messageErr, ErrWindowFull) && f.ackController != nil && !f.ackController.RecordExceedsLimit(record) {
						pendingFetched = cloneKafkaRecord(record)
						continue
					}
					// The record remains uncommitted. Keep this partition paused until
					// an operator reloads with viable limits, rather than reconnecting
					// forever or silently advancing past the undelivered record.
					admissionBlocked[record.Topic] = appendUniquePartition(admissionBlocked[record.Topic], record.Partition)
					pauseTopicPartitions[record.Topic] = appendUniquePartition(pauseTopicPartitions[record.Topic], record.Partition)
					continue
				}
				if batch, pause := checkpoints.addRecord(closeCtx, message, f.checkpointLimit); pause ||
					(f.ackController != nil && f.ackController.ShouldPause(record.Topic, record.Partition)) {
					pauseTopicPartitions[record.Topic] = append(pauseTopicPartitions[record.Topic], record.Partition)
				} else {
					f.waitForAccess(ctx, batch)
				}
			}
			if f.ackController != nil {
				decision, deadlineErr := f.ackController.DeadlineAction(time.Now())
				if deadlineErr != nil {
					f.log.Errorf("Kafka external acknowledgement deadline handling failed: %v", deadlineErr)
				}
				switch decision.Action {
				case DeadlineRedeliverPartitions:
					seek := make(map[string]map[int32]kgo.EpochOffset, len(decision.Redeliver))
					remove := make(map[string][]int32, len(decision.Redeliver))
					for _, target := range decision.Redeliver {
						if seek[target.Topic] == nil {
							seek[target.Topic] = make(map[int32]kgo.EpochOffset)
						}
						seek[target.Topic][target.Partition] = kgo.EpochOffset{Offset: target.Offset, Epoch: -1}
						remove[target.Topic] = appendUniquePartition(remove[target.Topic], target.Partition)
					}
					checkpoints.removeTopicPartitions(closeCtx, remove)
					cl.SetOffsets(seek)
					f.log.Warnf("Seeking %d Kafka partitions to redeliver %d expired records", len(decision.Redeliver), decision.ExpiredRecords)
				case DeadlinePause, DeadlineDeadLetterNotConfigured:
					for _, partition := range decision.Partitions {
						pauseTopicPartitions[partition.Topic] = append(pauseTopicPartitions[partition.Topic], partition.Partition)
					}
				}
			}

			// Walk all the disabled topic partitions and check whether any of
			// them can be resumed.
			resumeTopicPartitions := map[string][]int32{}
			globalCapacityReady := f.ackController == nil || f.ackController.HasCapacity()
			for pausedTopic, pausedPartitions := range cl.PauseFetchPartitions(pauseTopicPartitions) {
				for _, pausedPartition := range pausedPartitions {
					if partitionMayResume(
						!checkpoints.pauseFetch(pausedTopic, pausedPartition, f.checkpointLimit),
						f.ackController == nil || !f.ackController.ShouldPause(pausedTopic, pausedPartition),
						!containsPartition(admissionBlocked[pausedTopic], pausedPartition),
						!containsPartition(ownershipBlocked[pausedTopic], pausedPartition),
						globalCapacityReady,
					) {
						resumeTopicPartitions[pausedTopic] = append(resumeTopicPartitions[pausedTopic], pausedPartition)
					}
				}
			}
			if len(resumeTopicPartitions) > 0 {
				cl.ResumeFetchPartitions(resumeTopicPartitions)
			}
		}
	}()

	f.storeBatchChan(batchChan)
	return nil
}

func partitionMayResume(checkpointReady, acknowledgmentReady, admissionReady, ownershipReady, globalCapacityReady bool) bool {
	return checkpointReady && acknowledgmentReady && admissionReady && ownershipReady && globalCapacityReady
}

func acknowledgmentGroupCommitOptions(mode string, commitPeriod time.Duration) []kgo.Opt {
	if mode == AcknowledgmentModeOutput {
		return []kgo.Opt{kgo.AutoCommitMarks(), kgo.AutoCommitInterval(commitPeriod)}
	}
	if mode == AcknowledgmentModeExternal {
		// franz-go enables periodic offset commits by default. External
		// acknowledgment must advance Kafka exclusively through the signed
		// acknowledgment controller, never merely because a record was polled.
		return []kgo.Opt{kgo.DisableAutoCommit()}
	}
	return nil
}

func (f *franzKafkaReader) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	batchChan := f.getBatchChan()
	if batchChan == nil {
		return nil, nil, service.ErrNotConnected
	}

	var mAck batchWithAckFn
	var open bool
	select {
	case mAck, open = <-batchChan:
		if !open {
			return nil, nil, service.ErrNotConnected
		}
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	return mAck.batch, func(ctx context.Context, res error) error {
		// Res will always be nil because we initialize with service.AutoRetryNacks
		mAck.onAck()
		return nil
	}, nil
}

func (f *franzKafkaReader) Close(ctx context.Context) error {
	go func() {
		f.shutSig.TriggerSoftStop()
		if f.getBatchChan() == nil {
			// If the record chan is already nil then we might've not been
			// connected, so force the shutdown complete signal.
			f.shutSig.TriggerHasStopped()
		}
	}()
	select {
	case <-f.shutSig.HasStoppedChan():
	case <-ctx.Done():
		return ctx.Err()
	}
	if f.resetSupervisor != nil {
		if err := f.resetSupervisor.CloseContext(ctx); err != nil {
			return err
		}
		f.resetSupervisor = nil
	}
	return nil
}

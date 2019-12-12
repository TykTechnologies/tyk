package internal

import "time"

const (
	// app behavior

	// fixedHarvestPeriod is the period that fixed period data (metrics,
	// traces, and span events) is sent to New Relic.
	fixedHarvestPeriod = 60 * time.Second
	// defaultConfigurableEventHarvestMs is the period for custom, error,
	// and transaction events if the connect response's
	// "event_harvest_config.report_period_ms" is missing or invalid.
	defaultConfigurableEventHarvestMs = 60 * 1000
	// CollectorTimeout is the timeout used in the client for communication
	// with New Relic's servers.
	CollectorTimeout = 20 * time.Second
	// AppDataChanSize is the size of the channel that contains data sent
	// the app processor.
	AppDataChanSize           = 200
	failedMetricAttemptsLimit = 5
	failedEventsAttemptsLimit = 10
	// maxPayloadSizeInBytes specifies the maximum payload size in bytes that
	// should be sent to any endpoint
	maxPayloadSizeInBytes = 1000 * 1000

	// transaction behavior
	maxStackTraceFrames = 100
	// MaxTxnErrors is the maximum number of errors captured per
	// transaction.
	MaxTxnErrors      = 5
	maxTxnSlowQueries = 10

	startingTxnTraceNodes = 16
	maxTxnTraceNodes      = 256

	// harvest data
	maxMetrics          = 2 * 1000
	maxCustomEvents     = 10 * 1000
	maxTxnEvents        = 10 * 1000
	maxRegularTraces    = 1
	maxSyntheticsTraces = 20
	maxErrorEvents      = 100
	maxHarvestErrors    = 20
	maxHarvestSlowSQLs  = 10
	maxSpanEvents       = 1000

	// attributes
	attributeKeyLengthLimit   = 255
	attributeValueLengthLimit = 255
	attributeUserLimit        = 64
	// AttributeErrorLimit limits the number of extra attributes that can be
	// provided when noticing an error.
	AttributeErrorLimit       = 32
	attributeAgentLimit       = 255 - (attributeUserLimit + AttributeErrorLimit)
	customEventAttributeLimit = 64

	// Limits affecting Config validation are found in the config package.

	// RuntimeSamplerPeriod is the period of the runtime sampler.  Runtime
	// metrics should not depend on the sampler period, but the period must
	// be the same across instances.  For that reason, this value should not
	// be changed without notifying customers that they must update all
	// instance simultaneously for valid runtime metrics.
	RuntimeSamplerPeriod = 60 * time.Second

	txnNameCacheLimit = 40
)

package internal

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/newrelic/go-agent/internal/sysinfo"
)

// TxnEvent represents a transaction.
// https://source.datanerd.us/agents/agent-specs/blob/master/Transaction-Events-PORTED.md
// https://newrelic.atlassian.net/wiki/display/eng/Agent+Support+for+Synthetics%3A+Forced+Transaction+Traces+and+Analytic+Events
type TxnEvent struct {
	FinalName string
	Start     time.Time
	Duration  time.Duration
	Queuing   time.Duration
	Zone      ApdexZone
	Attrs     *Attributes
	DatastoreExternalTotals
	// CleanURL is not used in txn events, but is used in traced errors which embed TxnEvent.
	CleanURL string
}

// TxnData contains the recorded data of a transaction.
type TxnData struct {
	TxnEvent
	IsWeb          bool
	Errors         TxnErrors // Lazily initialized.
	Stop           time.Time
	ApdexThreshold time.Duration
	Exclusive      time.Duration

	finishedChildren time.Duration
	stamp            segmentStamp
	stack            []segmentFrame

	customSegments    map[string]*metricData
	datastoreSegments map[DatastoreMetricKey]*metricData
	externalSegments  map[externalMetricKey]*metricData

	TxnTrace

	SlowQueriesEnabled bool
	SlowQueryThreshold time.Duration
	SlowQueries        *slowQueries
}

type segmentStamp uint64

type segmentTime struct {
	Stamp segmentStamp
	Time  time.Time
}

// SegmentStartTime is embedded into the top level segments (rather than
// segmentTime) to minimize the structure sizes to minimize allocations.
type SegmentStartTime struct {
	Stamp segmentStamp
	Depth int
}

type segmentFrame struct {
	segmentTime
	children time.Duration
}

type segmentEnd struct {
	start     segmentTime
	stop      segmentTime
	duration  time.Duration
	exclusive time.Duration
}

const (
	datastoreProductUnknown   = "Unknown"
	datastoreOperationUnknown = "other"
)

// HasErrors indicates whether the transaction had errors.
func (t *TxnData) HasErrors() bool {
	return len(t.Errors) > 0
}

func (t *TxnData) time(now time.Time) segmentTime {
	// Update the stamp before using it so that a 0 stamp can be special.
	t.stamp++
	return segmentTime{
		Time:  now,
		Stamp: t.stamp,
	}
}

// TracerRootChildren is used to calculate a transaction's exclusive duration.
func TracerRootChildren(t *TxnData) time.Duration {
	var lostChildren time.Duration
	for i := 0; i < len(t.stack); i++ {
		lostChildren += t.stack[i].children
	}
	return t.finishedChildren + lostChildren
}

// StartSegment begins a segment.
func StartSegment(t *TxnData, now time.Time) SegmentStartTime {
	tm := t.time(now)
	t.stack = append(t.stack, segmentFrame{
		segmentTime: tm,
		children:    0,
	})

	return SegmentStartTime{
		Stamp: tm.Stamp,
		Depth: len(t.stack) - 1,
	}
}

var (
	errMalformedSegment = errors.New("segment identifier malformed: perhaps unsafe code has modified it?")
	errSegmentOrder     = errors.New(`improper segment use: the Transaction must be used ` +
		`in a single goroutine and segments must be ended in "last started first ended" order: ` +
		`see https://github.com/newrelic/go-agent/blob/master/GUIDE.md#segments`)
)

func endSegment(t *TxnData, start SegmentStartTime, now time.Time) (segmentEnd, error) {
	if 0 == start.Stamp {
		return segmentEnd{}, errMalformedSegment
	}
	if start.Depth >= len(t.stack) {
		return segmentEnd{}, errSegmentOrder
	}
	if start.Depth < 0 {
		return segmentEnd{}, errMalformedSegment
	}
	if start.Stamp != t.stack[start.Depth].Stamp {
		return segmentEnd{}, errSegmentOrder
	}

	var children time.Duration
	for i := start.Depth; i < len(t.stack); i++ {
		children += t.stack[i].children
	}
	s := segmentEnd{
		stop:  t.time(now),
		start: t.stack[start.Depth].segmentTime,
	}
	if s.stop.Time.After(s.start.Time) {
		s.duration = s.stop.Time.Sub(s.start.Time)
	}
	if s.duration > children {
		s.exclusive = s.duration - children
	}

	// Note that we expect (depth == (len(t.stack) - 1)).  However, if
	// (depth < (len(t.stack) - 1)), that's ok: could be a panic popped
	// some stack frames (and the consumer was not using defer).

	if 0 == start.Depth {
		t.finishedChildren += s.duration
	} else {
		t.stack[start.Depth-1].children += s.duration
	}

	t.stack = t.stack[0:start.Depth]

	return s, nil
}

// EndBasicSegment ends a basic segment.
func EndBasicSegment(t *TxnData, start SegmentStartTime, now time.Time, name string) error {
	end, err := endSegment(t, start, now)
	if nil != err {
		return err
	}
	if nil == t.customSegments {
		t.customSegments = make(map[string]*metricData)
	}
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := t.customSegments[name]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		t.customSegments[name] = cpy
	}

	if t.TxnTrace.considerNode(end) {
		t.TxnTrace.witnessNode(end, customSegmentMetric(name), nil)
	}

	return nil
}

// EndExternalSegment ends an external segment.
func EndExternalSegment(t *TxnData, start SegmentStartTime, now time.Time, u *url.URL) error {
	end, err := endSegment(t, start, now)
	if nil != err {
		return err
	}
	host := HostFromURL(u)
	if "" == host {
		host = "unknown"
	}
	key := externalMetricKey{
		Host: host,
		ExternalCrossProcessID:  "",
		ExternalTransactionName: "",
	}
	if nil == t.externalSegments {
		t.externalSegments = make(map[externalMetricKey]*metricData)
	}
	t.externalCallCount++
	t.externalDuration += end.duration
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := t.externalSegments[key]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		t.externalSegments[key] = cpy
	}

	if t.TxnTrace.considerNode(end) {
		t.TxnTrace.witnessNode(end, externalHostMetric(key), &traceNodeParams{
			CleanURL: SafeURL(u),
		})
	}

	return nil
}

// EndDatastoreParams contains the parameters for EndDatastoreSegment.
type EndDatastoreParams struct {
	Tracer             *TxnData
	Start              SegmentStartTime
	Now                time.Time
	Product            string
	Collection         string
	Operation          string
	ParameterizedQuery string
	QueryParameters    map[string]interface{}
	Host               string
	PortPathOrID       string
	Database           string
}

const (
	unknownDatastoreHost         = "unknown"
	unknownDatastorePortPathOrID = "unknown"
)

var (
	// ThisHost is the system hostname.
	ThisHost = func() string {
		if h, err := sysinfo.Hostname(); nil == err {
			return h
		}
		return unknownDatastoreHost
	}()
	hostsToReplace = map[string]struct{}{
		"localhost":       struct{}{},
		"127.0.0.1":       struct{}{},
		"0.0.0.0":         struct{}{},
		"0:0:0:0:0:0:0:1": struct{}{},
		"::1":             struct{}{},
		"0:0:0:0:0:0:0:0": struct{}{},
		"::":              struct{}{},
	}
)

func (t TxnData) slowQueryWorthy(d time.Duration) bool {
	return t.SlowQueriesEnabled && (d >= t.SlowQueryThreshold)
}

// EndDatastoreSegment ends a datastore segment.
func EndDatastoreSegment(p EndDatastoreParams) error {
	end, err := endSegment(p.Tracer, p.Start, p.Now)
	if nil != err {
		return err
	}
	if p.Operation == "" {
		p.Operation = datastoreOperationUnknown
	}
	if p.Product == "" {
		p.Product = datastoreProductUnknown
	}
	if p.Host == "" && p.PortPathOrID != "" {
		p.Host = unknownDatastoreHost
	}
	if p.PortPathOrID == "" && p.Host != "" {
		p.PortPathOrID = unknownDatastorePortPathOrID
	}
	if _, ok := hostsToReplace[p.Host]; ok {
		p.Host = ThisHost
	}

	// We still want to create a slowQuery if the consumer has not provided
	// a Query string since the stack trace has value.
	if p.ParameterizedQuery == "" {
		collection := p.Collection
		if "" == collection {
			collection = "unknown"
		}
		p.ParameterizedQuery = fmt.Sprintf(`'%s' on '%s' using '%s'`,
			p.Operation, collection, p.Product)
	}

	key := DatastoreMetricKey{
		Product:      p.Product,
		Collection:   p.Collection,
		Operation:    p.Operation,
		Host:         p.Host,
		PortPathOrID: p.PortPathOrID,
	}
	if nil == p.Tracer.datastoreSegments {
		p.Tracer.datastoreSegments = make(map[DatastoreMetricKey]*metricData)
	}
	p.Tracer.datastoreCallCount++
	p.Tracer.datastoreDuration += end.duration
	m := metricDataFromDuration(end.duration, end.exclusive)
	if data, ok := p.Tracer.datastoreSegments[key]; ok {
		data.aggregate(m)
	} else {
		// Use `new` in place of &m so that m is not
		// automatically moved to the heap.
		cpy := new(metricData)
		*cpy = m
		p.Tracer.datastoreSegments[key] = cpy
	}

	scopedMetric := datastoreScopedMetric(key)
	queryParams := vetQueryParameters(p.QueryParameters)

	if p.Tracer.TxnTrace.considerNode(end) {
		p.Tracer.TxnTrace.witnessNode(end, scopedMetric, &traceNodeParams{
			Host:            p.Host,
			PortPathOrID:    p.PortPathOrID,
			Database:        p.Database,
			Query:           p.ParameterizedQuery,
			queryParameters: queryParams,
		})
	}

	if p.Tracer.slowQueryWorthy(end.duration) {
		if nil == p.Tracer.SlowQueries {
			p.Tracer.SlowQueries = newSlowQueries(maxTxnSlowQueries)
		}
		// Frames to skip:
		//   this function
		//   endDatastore
		//   DatastoreSegment.End
		skipFrames := 3
		p.Tracer.SlowQueries.observeInstance(slowQueryInstance{
			Duration:           end.duration,
			DatastoreMetric:    scopedMetric,
			ParameterizedQuery: p.ParameterizedQuery,
			QueryParameters:    queryParams,
			Host:               p.Host,
			PortPathOrID:       p.PortPathOrID,
			DatabaseName:       p.Database,
			StackTrace:         GetStackTrace(skipFrames),
		})
	}

	return nil
}

// MergeBreakdownMetrics creates segment metrics.
func MergeBreakdownMetrics(t *TxnData, metrics *metricTable) {
	scope := t.FinalName
	isWeb := t.IsWeb
	// Custom Segment Metrics
	for key, data := range t.customSegments {
		name := customSegmentMetric(key)
		// Unscoped
		metrics.add(name, "", *data, unforced)
		// Scoped
		metrics.add(name, scope, *data, unforced)
	}

	// External Segment Metrics
	for key, data := range t.externalSegments {
		metrics.add(externalRollupMetric.all, "", *data, forced)
		metrics.add(externalRollupMetric.webOrOther(isWeb), "", *data, forced)

		hostMetric := externalHostMetric(key)
		metrics.add(hostMetric, "", *data, unforced)
		if "" != key.ExternalCrossProcessID && "" != key.ExternalTransactionName {
			txnMetric := externalTransactionMetric(key)

			// Unscoped CAT metrics
			metrics.add(externalAppMetric(key), "", *data, unforced)
			metrics.add(txnMetric, "", *data, unforced)

			// Scoped External Metric
			metrics.add(txnMetric, scope, *data, unforced)
		} else {
			// Scoped External Metric
			metrics.add(hostMetric, scope, *data, unforced)
		}
	}

	// Datastore Segment Metrics
	for key, data := range t.datastoreSegments {
		metrics.add(datastoreRollupMetric.all, "", *data, forced)
		metrics.add(datastoreRollupMetric.webOrOther(isWeb), "", *data, forced)

		product := datastoreProductMetric(key)
		metrics.add(product.all, "", *data, forced)
		metrics.add(product.webOrOther(isWeb), "", *data, forced)

		if key.Host != "" && key.PortPathOrID != "" {
			instance := datastoreInstanceMetric(key)
			metrics.add(instance, "", *data, unforced)
		}

		operation := datastoreOperationMetric(key)
		metrics.add(operation, "", *data, unforced)

		if "" != key.Collection {
			statement := datastoreStatementMetric(key)

			metrics.add(statement, "", *data, unforced)
			metrics.add(statement, scope, *data, unforced)
		} else {
			metrics.add(operation, scope, *data, unforced)
		}
	}
}

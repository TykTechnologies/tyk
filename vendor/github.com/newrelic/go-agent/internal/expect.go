package internal

import (
	"encoding/json"
	"fmt"
	"runtime"
)

var (
	// Unfortunately, the resolution of time.Now() on Windows is coarse: Two
	// sequential calls to time.Now() may return the same value, and tests
	// which expect non-zero durations may fail.  To avoid adding sleep
	// statements or mocking time.Now(), those tests are skipped on Windows.
	doDurationTests = runtime.GOOS != `windows`
)

// Validator is used for testing.
type Validator interface {
	Error(...interface{})
}

func validateStringField(v Validator, fieldName, v1, v2 string) {
	if v1 != v2 {
		v.Error(fieldName, v1, v2)
	}
}

type addValidatorField struct {
	field    interface{}
	original Validator
}

func (a addValidatorField) Error(fields ...interface{}) {
	fields = append([]interface{}{a.field}, fields...)
	a.original.Error(fields...)
}

// ExtendValidator is used to add more context to a validator.
func ExtendValidator(v Validator, field interface{}) Validator {
	return addValidatorField{
		field:    field,
		original: v,
	}
}

// WantMetric is a metric expectation.  If Data is nil, then any data values are
// acceptable.
type WantMetric struct {
	Name   string
	Scope  string
	Forced interface{} // true, false, or nil
	Data   []float64
}

// WantError is a traced error expectation.
type WantError struct {
	TxnName         string
	Msg             string
	Klass           string
	Caller          string
	URL             string
	UserAttributes  map[string]interface{}
	AgentAttributes map[string]interface{}
}

func uniquePointer() *struct{} {
	s := struct{}{}
	return &s
}

var (
	// MatchAnything is for use when matching attributes.
	MatchAnything = uniquePointer()
)

// WantEvent is a transaction or error event expectation.
type WantEvent struct {
	Intrinsics      map[string]interface{}
	UserAttributes  map[string]interface{}
	AgentAttributes map[string]interface{}
}

// WantTxnTrace is a transaction trace expectation.
type WantTxnTrace struct {
	MetricName      string
	CleanURL        string
	NumSegments     int
	UserAttributes  map[string]interface{}
	AgentAttributes map[string]interface{}
}

// WantSlowQuery is a slowQuery expectation.
type WantSlowQuery struct {
	Count        int32
	MetricName   string
	Query        string
	TxnName      string
	TxnURL       string
	DatabaseName string
	Host         string
	PortPathOrID string
	Params       map[string]interface{}
}

// Expect exposes methods that allow for testing whether the correct data was
// captured.
type Expect interface {
	ExpectCustomEvents(t Validator, want []WantEvent)
	ExpectErrors(t Validator, want []WantError)
	ExpectErrorEvents(t Validator, want []WantEvent)
	ExpectTxnEvents(t Validator, want []WantEvent)
	ExpectMetrics(t Validator, want []WantMetric)
	ExpectTxnTraces(t Validator, want []WantTxnTrace)
	ExpectSlowQueries(t Validator, want []WantSlowQuery)
}

func expectMetricField(t Validator, id metricID, v1, v2 float64, fieldName string) {
	if v1 != v2 {
		t.Error("metric fields do not match", id, v1, v2, fieldName)
	}
}

// ExpectMetrics allows testing of metrics.
func ExpectMetrics(t Validator, mt *metricTable, expect []WantMetric) {
	if len(mt.metrics) != len(expect) {
		t.Error("metric counts do not match expectations", len(mt.metrics), len(expect))
	}
	expectedIds := make(map[metricID]struct{})
	for _, e := range expect {
		id := metricID{Name: e.Name, Scope: e.Scope}
		expectedIds[id] = struct{}{}
		m := mt.metrics[id]
		if nil == m {
			t.Error("unable to find metric", id)
			continue
		}

		if b, ok := e.Forced.(bool); ok {
			if b != (forced == m.forced) {
				t.Error("metric forced incorrect", b, m.forced, id)
			}
		}

		if nil != e.Data {
			expectMetricField(t, id, e.Data[0], m.data.countSatisfied, "countSatisfied")
			expectMetricField(t, id, e.Data[1], m.data.totalTolerated, "totalTolerated")
			expectMetricField(t, id, e.Data[2], m.data.exclusiveFailed, "exclusiveFailed")
			expectMetricField(t, id, e.Data[3], m.data.min, "min")
			expectMetricField(t, id, e.Data[4], m.data.max, "max")
			expectMetricField(t, id, e.Data[5], m.data.sumSquares, "sumSquares")
		}
	}
	for id := range mt.metrics {
		if _, ok := expectedIds[id]; !ok {
			t.Error("expected metrics does not contain", id.Name, id.Scope)
		}
	}
}

func expectAttributes(v Validator, exists map[string]interface{}, expect map[string]interface{}) {
	// TODO: This params comparison can be made smarter: Alert differences
	// based on sub/super set behavior.
	if len(exists) != len(expect) {
		v.Error("attributes length difference", len(exists), len(expect))
	}
	for key, val := range expect {
		found, ok := exists[key]
		if !ok {
			v.Error("expected attribute not found: ", key)
			continue
		}
		if val == MatchAnything {
			continue
		}
		v1 := fmt.Sprint(found)
		v2 := fmt.Sprint(val)
		if v1 != v2 {
			v.Error("value difference", fmt.Sprintf("key=%s", key), v1, v2)
		}
	}
}

// ExpectCustomEvents allows testing of custom events.
func ExpectCustomEvents(v Validator, cs *customEvents, expect []WantEvent) {
	if len(cs.events.events) != len(expect) {
		v.Error("number of custom events does not match", len(cs.events.events),
			len(expect))
		return
	}
	for i, e := range expect {
		event, ok := cs.events.events[i].jsonWriter.(*CustomEvent)
		if !ok {
			v.Error("wrong custom event")
		} else {
			expectEvent(v, event, e)
		}
	}
}

func expectEvent(v Validator, e json.Marshaler, expect WantEvent) {
	js, err := e.MarshalJSON()
	if nil != err {
		v.Error("unable to marshal event", err)
		return
	}
	var event []map[string]interface{}
	err = json.Unmarshal(js, &event)
	if nil != err {
		v.Error("unable to parse event json", err)
		return
	}
	intrinsics := event[0]
	userAttributes := event[1]
	agentAttributes := event[2]

	if nil != expect.Intrinsics {
		expectAttributes(v, intrinsics, expect.Intrinsics)
	}
	if nil != expect.UserAttributes {
		expectAttributes(v, userAttributes, expect.UserAttributes)
	}
	if nil != expect.AgentAttributes {
		expectAttributes(v, agentAttributes, expect.AgentAttributes)
	}
}

// Second attributes have priority.
func mergeAttributes(a1, a2 map[string]interface{}) map[string]interface{} {
	a := make(map[string]interface{})
	for k, v := range a1 {
		a[k] = v
	}
	for k, v := range a2 {
		a[k] = v
	}
	return a
}

// ExpectErrorEvents allows testing of error events.
func ExpectErrorEvents(v Validator, events *errorEvents, expect []WantEvent) {
	if len(events.events.events) != len(expect) {
		v.Error("number of custom events does not match",
			len(events.events.events), len(expect))
		return
	}
	for i, e := range expect {
		event, ok := events.events.events[i].jsonWriter.(*ErrorEvent)
		if !ok {
			v.Error("wrong error event")
		} else {
			if nil != e.Intrinsics {
				e.Intrinsics = mergeAttributes(map[string]interface{}{
					// The following intrinsics should always be present in
					// error events:
					"type":      "TransactionError",
					"timestamp": MatchAnything,
					"duration":  MatchAnything,
				}, e.Intrinsics)
			}
			expectEvent(v, event, e)
		}
	}
}

// ExpectTxnEvents allows testing of txn events.
func ExpectTxnEvents(v Validator, events *txnEvents, expect []WantEvent) {
	if len(events.events.events) != len(expect) {
		v.Error("number of txn events does not match",
			len(events.events.events), len(expect))
		return
	}
	for i, e := range expect {
		event, ok := events.events.events[i].jsonWriter.(*TxnEvent)
		if !ok {
			v.Error("wrong txn event")
		} else {
			if nil != e.Intrinsics {
				e.Intrinsics = mergeAttributes(map[string]interface{}{
					// The following intrinsics should always be present in
					// txn events:
					"type":      "Transaction",
					"timestamp": MatchAnything,
					"duration":  MatchAnything,
				}, e.Intrinsics)
			}
			expectEvent(v, event, e)
		}
	}
}

func expectError(v Validator, err *tracedError, expect WantError) {
	caller := topCallerNameBase(err.ErrorData.Stack)
	validateStringField(v, "caller", expect.Caller, caller)
	validateStringField(v, "txnName", expect.TxnName, err.FinalName)
	validateStringField(v, "klass", expect.Klass, err.Klass)
	validateStringField(v, "msg", expect.Msg, err.Msg)
	validateStringField(v, "URL", expect.URL, err.CleanURL)
	if nil != expect.UserAttributes {
		expectAttributes(v, getUserAttributes(err.Attrs, destError), expect.UserAttributes)
	}
	if nil != expect.AgentAttributes {
		expectAttributes(v, getAgentAttributes(err.Attrs, destError), expect.AgentAttributes)
	}
}

// ExpectErrors allows testing of errors.
func ExpectErrors(v Validator, errors harvestErrors, expect []WantError) {
	if len(errors) != len(expect) {
		v.Error("number of errors mismatch", len(errors), len(expect))
		return
	}
	for i, e := range expect {
		expectError(v, errors[i], e)
	}
}

func expectTxnTrace(v Validator, trace *HarvestTrace, expect WantTxnTrace) {
	if doDurationTests && 0 == trace.Duration {
		v.Error("zero trace duration")
	}
	validateStringField(v, "metric name", expect.MetricName, trace.FinalName)
	validateStringField(v, "request url", expect.CleanURL, trace.CleanURL)
	if nil != expect.UserAttributes {
		expectAttributes(v, getUserAttributes(trace.Attrs, destTxnTrace), expect.UserAttributes)
	}
	if nil != expect.AgentAttributes {
		expectAttributes(v, getAgentAttributes(trace.Attrs, destTxnTrace), expect.AgentAttributes)
	}
	if expect.NumSegments != len(trace.Trace.nodes) {
		v.Error("wrong number of segments", expect.NumSegments, len(trace.Trace.nodes))
	}
}

// ExpectTxnTraces allows testing of transaction traces.
func ExpectTxnTraces(v Validator, traces *harvestTraces, want []WantTxnTrace) {
	if len(want) == 0 {
		if nil != traces.trace {
			v.Error("trace exists when not expected")
		}
	} else if len(want) > 1 {
		v.Error("too many traces expected")
	} else {
		if nil == traces.trace {
			v.Error("missing expected trace")
		} else {
			expectTxnTrace(v, traces.trace, want[0])
		}
	}
}

func expectSlowQuery(t Validator, slowQuery *slowQuery, want WantSlowQuery) {
	if slowQuery.Count != want.Count {
		t.Error("wrong Count field", slowQuery.Count, want.Count)
	}
	validateStringField(t, "MetricName", slowQuery.DatastoreMetric, want.MetricName)
	validateStringField(t, "Query", slowQuery.ParameterizedQuery, want.Query)
	validateStringField(t, "TxnName", slowQuery.TxnName, want.TxnName)
	validateStringField(t, "TxnURL", slowQuery.TxnURL, want.TxnURL)
	validateStringField(t, "DatabaseName", slowQuery.DatabaseName, want.DatabaseName)
	validateStringField(t, "Host", slowQuery.Host, want.Host)
	validateStringField(t, "PortPathOrID", slowQuery.PortPathOrID, want.PortPathOrID)
	expectAttributes(t, map[string]interface{}(slowQuery.QueryParameters), want.Params)
}

// ExpectSlowQueries allows testing of slow queries.
func ExpectSlowQueries(t Validator, slowQueries *slowQueries, want []WantSlowQuery) {
	if len(want) != len(slowQueries.priorityQueue) {
		t.Error("wrong number of slow queries",
			"expected", len(want), "got", len(slowQueries.priorityQueue))
		return
	}
	for _, s := range want {
		idx, ok := slowQueries.lookup[s.Query]
		if !ok {
			t.Error("unable to find slow query", s.Query)
			continue
		}
		expectSlowQuery(t, slowQueries.priorityQueue[idx], s)
	}
}

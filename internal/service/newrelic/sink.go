package newrelic

import (
	"fmt"
	"strconv"

	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/gocraft/health"
)

type Sink struct {
	relic *newrelic.Application
	health.Sink
}

func NewSink(relic *newrelic.Application) *Sink {
	return &Sink{
		relic: relic,
	}
}

func (s *Sink) EmitEvent(job string, event string, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event, makeParams(kvs))
}

func (s *Sink) EmitEventErr(job string, event string, err error, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":msg:"+err.Error(), makeParams(kvs))
}

func (s *Sink) EmitTiming(job string, event string, nanoseconds int64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":duration_ns:"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
}

func (s *Sink) EmitComplete(job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":health:"+status.String()+":duration_ns:"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
}

func (s *Sink) EmitGauge(job string, event string, value float64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":value:"+fmt.Sprintf("%.2f", value), makeParams(kvs))
}

func makeParams(kvs map[string]string) (params map[string]interface{}) {
	params = make(map[string]interface{}, len(kvs))
	for k, v := range kvs {
		params[k] = v
	}
	return
}

package newrelic

import (
	"fmt"
	"strconv"

	"github.com/newrelic/go-agent/v3/integrations/nrgorilla"
	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/gocraft/health"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type (
	Application  = newrelic.Application
	Transaction  = newrelic.Transaction
	ConfigOption = newrelic.ConfigOption
)

var (
	NewApplication = newrelic.NewApplication

	ConfigLogger                   = newrelic.ConfigLogger
	ConfigEnabled                  = newrelic.ConfigEnabled
	ConfigAppName                  = newrelic.ConfigAppName
	ConfigLicense                  = newrelic.ConfigLicense
	ConfigDistributedTracerEnabled = newrelic.ConfigDistributedTracerEnabled
)

// AddNewRelicInstrumentation adds NewRelic instrumentation to the router
func AddNewRelicInstrumentation(app *newrelic.Application, r *mux.Router) {
	nrgorilla.InstrumentRoutes(r, app)
}

type Logger struct{ *logrus.Entry }

func NewLogger(e *logrus.Entry) *Logger {
	return &Logger{e}
}

func (l *Logger) Error(msg string, c map[string]interface{}) {
	l.WithFields(c).Error(msg)
}
func (l *Logger) Warn(msg string, c map[string]interface{}) {
	l.WithFields(c).Warn(msg)
}
func (l *Logger) Info(msg string, c map[string]interface{}) {
	l.WithFields(c).Info(msg)
}
func (l *Logger) Debug(msg string, c map[string]interface{}) {
	l.WithFields(c).Debug(msg)
}
func (l *Logger) DebugEnabled() bool {
	return l.Level >= logrus.DebugLevel
}

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
	s.relic.RecordCustomEvent(job+":"+event+":dur(ns):"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
}

func (s *Sink) EmitComplete(job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":health:"+status.String()+":dur(ns):"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
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

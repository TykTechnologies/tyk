package gateway

import (
	"fmt"
	"strconv"

	"github.com/gocraft/health"
	"github.com/gorilla/mux"
	newrelic "github.com/newrelic/go-agent"
	"github.com/newrelic/go-agent/_integrations/nrgorilla/v1"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/config"
)

// SetupNewRelic creates new newrelic.Application instance
func SetupNewRelic() (app newrelic.Application) {
	var err error
	logger := log.WithFields(logrus.Fields{"prefix": "newrelic"})

	logger.Info("Initializing NewRelic...")

	cfg := newrelic.NewConfig(config.Global().NewRelic.AppName, config.Global().NewRelic.LicenseKey)
	if config.Global().NewRelic.AppName != "" {
		cfg.Enabled = true
	}
	cfg.Logger = &newRelicLogger{logger}

	if app, err = newrelic.NewApplication(cfg); err != nil {
		logger.Warn("Error initializing NewRelic, skipping... ", err)
		return
	}

	instrument.AddSink(&newRelicSink{relic: app})
	logger.Info("NewRelic initialized")

	return
}

// AddNewRelicInstrumentation adds NewRelic instrumentation to the router
func AddNewRelicInstrumentation(app newrelic.Application, r *mux.Router) {
	if app != nil {
		nrgorilla.InstrumentRoutes(r, app)
	}
}

type newRelicLogger struct{ *logrus.Entry }

func (l *newRelicLogger) Error(msg string, c map[string]interface{}) {
	l.WithFields(c).Error(msg)
}
func (l *newRelicLogger) Warn(msg string, c map[string]interface{}) {
	l.WithFields(c).Warn(msg)
}
func (l *newRelicLogger) Info(msg string, c map[string]interface{}) {
	l.WithFields(c).Info(msg)
}
func (l *newRelicLogger) Debug(msg string, c map[string]interface{}) {
	l.WithFields(c).Debug(msg)
}
func (l *newRelicLogger) DebugEnabled() bool {
	return l.Level >= logrus.DebugLevel
}

type newRelicSink struct {
	relic newrelic.Application
	health.Sink
}

func (s *newRelicSink) EmitEvent(job string, event string, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event, makeParams(kvs))
}

func (s *newRelicSink) EmitEventErr(job string, event string, err error, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":msg:"+err.Error(), makeParams(kvs))
}

func (s *newRelicSink) EmitTiming(job string, event string, nanoseconds int64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":dur(ns):"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
}

func (s *newRelicSink) EmitComplete(job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":health:"+status.String()+":dur(ns):"+strconv.FormatInt(nanoseconds, 10), makeParams(kvs))
}

func (s *newRelicSink) EmitGauge(job string, event string, value float64, kvs map[string]string) {
	s.relic.RecordCustomEvent(job+":"+event+":value:"+fmt.Sprintf("%.2f", value), makeParams(kvs))
}

func makeParams(kvs map[string]string) (params map[string]interface{}) {
	params = make(map[string]interface{}, len(kvs))
	for k, v := range kvs {
		params[k] = v
	}
	return
}

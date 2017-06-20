package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/gocraft/health"
	"github.com/newrelic/go-agent"
	"github.com/gorilla/mux"
	"github.com/newrelic/go-agent/_integrations/nrgorilla/v1"
)

func setupNewRelic() {
	log.WithFields(logrus.Fields{
		"prefix": "newrelic",
	}).Info("Initializing NewRelic...")

	cfg := newrelic.NewConfig(config.NewRelic.AppName, config.NewRelic.License)
	//cfg.Logger = nrlogrus.StandardLogger()
	cfg.Logger = newrelic.NewDebugLogger(os.Stdout)
	app, err := newrelic.NewApplication(cfg)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "newrelic",
		}).Warn("Error initializing NewRelic, skipping... ", err)
		return
	}
	router.PostProcess(NewrelicRouterInstrumentation(app))
	instrument.AddSink(&newRelicSink{relic: app})
}

func NewrelicRouterInstrumentation(app newrelic.Application) RouteProcessor {
	return func(r *mux.Router) { nrgorilla.InstrumentRoutes(r, app) }
}

type newRelicSink struct {
	relic newrelic.Application
	health.Sink
}

func (s *newRelicSink) EmitEvent(job string, event string, kvs map[string]string) {
	params := make(map[string]interface{}, len(kvs))
	for k, v := range kvs {
		params[k] = v
	}
	s.relic.RecordCustomEvent(job+":"+event, params)
}

func (s *newRelicSink) EmitEventErr(job string, event string, err error, kvs map[string]string) {

}

func (s *newRelicSink) EmitTiming(job string, event string, nanoseconds int64, kvs map[string]string) {

}

func (s *newRelicSink) EmitComplete(job string, status health.CompletionStatus, nanoseconds int64, kvs map[string]string) {

}

func (s *newRelicSink) EmitGauge(job string, event string, value float64, kvs map[string]string) {

}

package gateway

import (
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/gocraft/health"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/request"
)

var applicationGCStats = debug.GCStats{}
var instrument = health.NewStream()
var instrumentationEnabled bool

// setupInstrumentation handles all the initialisation of the instrumentation handler
func (gw *Gateway) setupInstrumentation() {
	switch {
	case *cli.LogInstrumentation:
	case os.Getenv("TYK_INSTRUMENTATION") == "1":
	default:
		return
	}

	gwConfig := gw.GetConfig()
	if gwConfig.StatsdConnectionString == "" {
		log.Error("Instrumentation is enabled, but no connectionstring set for statsd")
		return
	}

	instrumentationEnabled = true

	log.Info("Sending stats to: ", gwConfig.StatsdConnectionString, " with prefix: ", gwConfig.StatsdPrefix)
	statsdSink, err := NewStatsDSink(gwConfig.StatsdConnectionString,
		&StatsDSinkOptions{Prefix: gwConfig.StatsdPrefix})

	if err != nil {
		log.Fatal("Failed to start StatsD check: ", err)
	}

	log.Info("StatsD instrumentation sink started")
	instrument.AddSink(statsdSink)

	gw.MonitorApplicationInstrumentation()
}

// setupPrometheusInstrumentation initializes Prometheus metrics collection and HTTP endpoint
func (gw *Gateway) setupPrometheusInstrumentation() {
	gwConfig := gw.GetConfig()

	if !gwConfig.Prometheus.Enabled {
		return
	}

	log.WithFields(logrus.Fields{
		"per_api_metrics": gwConfig.Prometheus.EnablePerAPIMetrics,
	}).Info("Initializing Prometheus metrics...")

	gw.PrometheusMetrics = NewPrometheusMetrics(gw, gwConfig.Prometheus.MetricPrefix, gwConfig.Prometheus.EnablePerAPIMetrics)

	// Register optional Go and process collectors
	gw.PrometheusMetrics.RegisterGoCollectors(
		gwConfig.Prometheus.EnableGoCollector,
		gwConfig.Prometheus.EnableProcessCollector,
	)

	// Add Prometheus sink to instrument stream
	prometheusSink := NewPrometheusSink(gw.PrometheusMetrics)
	instrument.AddSink(prometheusSink)

	// Start metrics collection
	gw.PrometheusMetrics.StartMetricsCollection(gw.ctx)

	// Start Prometheus HTTP server
	gw.startPrometheusServer()

	log.WithFields(logrus.Fields{
		"listen_address": gwConfig.Prometheus.ListenAddress,
		"path":           gwConfig.Prometheus.Path,
		"prefix":         gwConfig.Prometheus.MetricPrefix,
	}).Info("Prometheus metrics endpoint started")
}

// startPrometheusServer starts the HTTP server for Prometheus metrics endpoint
func (gw *Gateway) startPrometheusServer() {
	gwConfig := gw.GetConfig()

	mux := http.NewServeMux()
	mux.Handle(gwConfig.Prometheus.Path, gw.PrometheusMetrics.Handler())

	server := &http.Server{
		Addr:         gwConfig.Prometheus.ListenAddress,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	gw.prometheusServerMu.Lock()
	gw.prometheusServer = server
	gw.prometheusServerMu.Unlock()

	go func() {
		log.WithFields(logrus.Fields{
			"address": gwConfig.Prometheus.ListenAddress,
		}).Info("Starting Prometheus metrics server...")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Prometheus metrics server failed to start")
		}
	}()
}

// InstrumentationMW will set basic instrumentation events, variables and timers on API jobs
func InstrumentationMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		job := instrument.NewJob("SystemAPICall")

		next.ServeHTTP(w, r)
		job.EventKv("called", health.Kvs{
			"from_ip":  request.RealIP(r),
			"method":   r.Method,
			"endpoint": r.URL.Path,
			"raw_url":  r.URL.String(),
			"size":     strconv.Itoa(int(r.ContentLength)),
		})
		job.Complete(health.Success)
	})
}

func (gw *Gateway) MonitorApplicationInstrumentation() {
	log.Info("Starting application monitoring...")
	go func() {
		job := instrument.NewJob("GCActivity")
		job_rl := instrument.NewJob("Load")
		metadata := health.Kvs{"host": gw.hostDetails.Hostname}
		applicationGCStats.PauseQuantiles = make([]time.Duration, 5)

		for {
			debug.ReadGCStats(&applicationGCStats)
			job.GaugeKv("pauses_quantile_min", float64(applicationGCStats.PauseQuantiles[0].Nanoseconds()), metadata)
			job.GaugeKv("pauses_quantile_25", float64(applicationGCStats.PauseQuantiles[1].Nanoseconds()), metadata)
			job.GaugeKv("pauses_quantile_50", float64(applicationGCStats.PauseQuantiles[2].Nanoseconds()), metadata)
			job.GaugeKv("pauses_quantile_75", float64(applicationGCStats.PauseQuantiles[3].Nanoseconds()), metadata)
			job.GaugeKv("pauses_quantile_max", float64(applicationGCStats.PauseQuantiles[4].Nanoseconds()), metadata)

			job_rl.GaugeKv("rps", float64(GlobalRate.Rate()), metadata)
			time.Sleep(5 * time.Second)
		}
	}()
}

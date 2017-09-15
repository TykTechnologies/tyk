package main

import (
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/gocraft/health"
)

var applicationGCStats = debug.GCStats{}
var instrument = health.NewStream()

// setupInstrumentation handles all the intialisation of the instrumentation handler
func setupInstrumentation(arguments map[string]interface{}) {
	switch {
	case arguments["--log-instrumentation"] == true:
	case os.Getenv("TYK_INSTRUMENTATION") == "1":
	default:
		return
	}

	if globalConf.StatsdConnectionString == "" {
		log.Error("Instrumentation is enabled, but no connectionstring set for statsd")
		return
	}

	log.Info("Sending stats to: ", globalConf.StatsdConnectionString, " with prefix: ", globalConf.StatsdPrefix)
	statsdSink, err := NewStatsDSink(globalConf.StatsdConnectionString,
		&StatsDSinkOptions{Prefix: globalConf.StatsdPrefix})

	if err != nil {
		log.Fatal("Failed to start StatsD check: ", err)
	}

	log.Info("StatsD instrumentation sink started")
	instrument.AddSink(statsdSink)

	MonitorApplicationInstrumentation()
}

// InstrumentationMW will set basic instrumentation events, variables and timers on API jobs
func InstrumentationMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		job := instrument.NewJob("SystemAPICall")

		next.ServeHTTP(w, r)
		job.EventKv("called", health.Kvs{
			"from_ip":  requestIP(r),
			"method":   r.Method,
			"endpoint": r.URL.Path,
			"raw_url":  r.URL.String(),
			"size":     strconv.Itoa(int(r.ContentLength)),
		})
		job.Complete(health.Success)
	})
}

func MonitorApplicationInstrumentation() {
	log.Info("Starting application monitoring...")
	go func() {
		job := instrument.NewJob("GCActivity")
		job_rl := instrument.NewJob("Load")
		metadata := health.Kvs{"host": hostDetails.Hostname}
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

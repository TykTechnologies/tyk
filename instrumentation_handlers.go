package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/gocraft/health"
)

var applicationGCStats debug.GCStats = debug.GCStats{}
var instrument = health.NewStream()

// SetupInstrumentation handles all the intialisation of the instrumentation handler
func SetupInstrumentation(enabled bool) {
	if !enabled {
		return
	}

	// TODO: REMOVE THIS BLOCK
	log.Warning("TODO: Disable auto-instrumentation logging")
	instrument.AddSink(&health.WriterSink{os.Stdout})

	log.Info("-------------- StatsD Sink Starting --------------")
	statsdSink, err := health.NewStatsDSink("statsd.hostedgraphite.com:8125",
		&health.StatsDSinkOptions{Prefix: "dc3e8f2f-c8fe-48f8-a389-fefd88855a98"})

	log.Info("-------------- StatsD Sink Started! --------------")
	if err != nil {
		log.Fatal("Failed to start StatsD check: ", err)
		return
	}

	instrument.AddSink(statsdSink)
	// REMOVE ABOVE THIS LINE

	MonitorApplicationInstrumentation()
}

// InstrumentationMW will set basic instrumentation events, variables and timers on API jobs
func InstrumentationMW(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		job := instrument.NewJob("gwSystemAPICall")

		handler(w, r)
		job.EventKv("called", health.Kvs{
			"from_ip":  fmt.Sprint(r.RemoteAddr),
			"method":   r.Method,
			"endpoint": r.URL.Path,
			"raw_url":  r.URL.String(),
			"size":     strconv.Itoa(int(r.ContentLength)),
		})
		job.Complete(health.Success)
	}
}

func MonitorApplicationInstrumentation() {
	job := instrument.NewJob("gwGCActivity")
	job_rl := instrument.NewJob("gwLoad")
	metadata := health.Kvs{"host": HostDetails.Hostname}
	applicationGCStats.PauseQuantiles = make([]time.Duration, 5)

	log.Info("Starting application monitoring...")
	go func() {
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

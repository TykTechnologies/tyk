package main

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/gocraft/health"
)

var applicationGCStats debug.GCStats = debug.GCStats{}

// InstrumentationMW will set basic instrumentation events, variables and timers on API jobs
func InstrumentationMW(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		job := instrument.NewJob("gw_api_call")

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
	job := instrument.NewJob("gw_gc_activity")
	job_rl := instrument.NewJob("gw_load")
	metadata := health.Kvs{"host": DRLManager.ThisServerID}
	applicationGCStats.PauseQuantiles = make([]time.Duration, 5)

	log.Info("Starting application monitoring...")
	go func() {
		for {
			log.Info("READING")
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

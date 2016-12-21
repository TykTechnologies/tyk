package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gocraft/health"
)

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

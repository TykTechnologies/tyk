package test

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"

	_ "net/http/pprof"
)

var initOnce sync.Once

func InitTestMain(_ context.Context, _ *testing.M) {
	initOnce.Do(func() {
		// Poor mans resource monitoring, prints runtime stats into logs
		if interval := os.Getenv("TEST_MONITOR_INTERVAL"); interval != "" {
			val, _ := strconv.Atoi(interval)
			if val < 1 {
				val = 1
			}
			go NewMonitor(val)
		}

		// Enable pprof server from test env
		if pprof := os.Getenv("TEST_PPROF_ENABLE"); pprof == "1" {
			var listen string
			if listen = os.Getenv("TEST_PPROF_ADDR"); listen == "" {
				listen = ":12345"
			}
			go func() {
				log.Printf("Starting pprof on addr=%q", listen)
				_ = http.ListenAndServe(listen, nil)
			}()
		}
	})
}

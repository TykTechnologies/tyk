package test

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	_ "net/http/pprof"
)

var initOnce sync.Once

func init() {
	if interval := os.Getenv("TEST_MONITOR_INTERVAL"); interval != "" {
		initOnce.Do(func() {
			val, _ := strconv.Atoi(interval)
			if val < 1 {
				val = 1
			}
			go NewMonitor(val)
		})
	}

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

}

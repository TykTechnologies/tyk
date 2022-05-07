package test

import (
	"os"
	"strconv"
	"sync"
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
}

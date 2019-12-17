package storage

import (
	"sync"
	"time"

	"github.com/asecurityteam/rolling"
)

// HealthSTore implements Health interface, this stores values in memory.
type HealthStore struct {
	policies       map[string]*rolling.TimePolicy
	bucketDuration time.Duration
	buckets        int
	mu             sync.RWMutex
}

func (h *HealthStore) Connect() {
	h.policies = make(map[string]*rolling.TimePolicy)
}

func (h *HealthStore) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	return 0, nil
}

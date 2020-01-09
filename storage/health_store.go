package storage

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

var _ Health = (*HealthStore)(nil)

// NewHalthStore returns a new HealthStore instance with duration in seconds
func NewHalthStore(duration int64) *HealthStore {
	return &HealthStore{
		bucketDuration: duration,
		buckets:        duration,
		policies:       new(sync.Map),
		now:            time.Now,
		divisor:        healthCountsDivisor,
	}
}

func nanoTime() int64 {
	return time.Now().UnixNano()
}

// HealthStore implements Health interface, this stores values in memory.
type HealthStore struct {
	policies       *sync.Map
	bucketDuration int64
	buckets        int64
	now            func() time.Time
	divisor        func() float64
}

func (h *HealthStore) get(key string) *slidingSortedSet {
	if v, ok := h.policies.Load(key); ok {
		return v.(*slidingSortedSet)
	}
	p := newTimeSet(time.Duration(h.bucketDuration)*time.Second, h.now)
	h.policies.Store(key, p)
	return p
}

// Connect initializes policy store
func (h *HealthStore) Connect() bool {
	h.policies = new(sync.Map)
	if h.bucketDuration == 0 {
		h.bucketDuration = 60
	}
	if h.buckets == 0 {
		h.buckets = h.bucketDuration
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.divisor == nil {
		h.divisor = healthCountsDivisor
	}
	return true
}

// SetRollingWindow adds val into a rolling time window and returns the total
// count of items added in the said window.
//
// When val is "-1" value is set to time.Now().UnixNano()
//
// per and pipeline are not used they are here to satisfy the interface(which
// was modelled with redis in mind). The second returned value is always nil, so
// be careful.
func (h *HealthStore) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	p := h.get(key)
	k, v := h.kv(val)
	return p.Set(k, v)
}

// CalculateHealthAVG returns the average by counting all items in the buckets
// window divided by their window size.
//
// NOTE:(gernest)  There is no documentation on the redis code. I am just trying
// to replicate similar results here , I have no clue on why are we doing this,
// because meaning metric here is average which we can already calculate.
func (h *HealthStore) CalculateHealthAVG(keyName string, per int64, val string, pipeline bool) (float64, error) {
	p := h.get(keyName)
	k, v := h.kv(val)
	count, _ := p.Set(k, v)
	divisor := h.divisor()
	if count > 0 {
		return roundValue((float64(count) - 1) / divisor), nil
	}
	return 0, nil
}

func (h *HealthStore) kv(valueOveride string) (k, v int64) {
	if valueOveride != "-1" {
		p := strings.Split(valueOveride, ".")
		if len(p) > 0 {
			k, _ = strconv.ParseInt(p[0], 10, 64)
			v, _ = strconv.ParseInt(p[1], 10, 64)
		}
	} else {
		k = h.now().UnixNano()
		v = k
	}
	return
}

func countFunc(w [][]int64) int64 {
	var result int64
	for _, bucket := range w {
		for range bucket {
			result = result + 1
		}
	}
	return result
}

// CalculateHealthMicroAVG returns the average by summing all values added in the
// window divided by their total count.
func (h *HealthStore) CalculateHealthMicroAVG(keyName string, per int64, val string, pipeline bool) (float64, error) {
	p := h.get(keyName)
	k, v := h.kv(val)
	_, vals := p.Set(k, v)
	var runningTotal int64
	for _, v := range vals {

		vInt := v.(int64)
		runningTotal += vInt
	}
	if len(vals) > 0 {
		return roundValue(float64(runningTotal / int64(len(vals)))), nil
	}
	return 0, nil
}

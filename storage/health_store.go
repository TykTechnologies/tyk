package storage

import (
	"strconv"
	"sync"
	"time"
)

var _ Health = (*HealthStore)(nil)

// NewHalthStore returns a new HealthStore instance with duration in seconds
func NewHalthStore(duration int) *HealthStore {
	return &HealthStore{
		bucketDuration: duration,
		buckets:        duration,
		policies:       new(sync.Map),
		now:            nanoTime,
	}
}

func nanoTime() int64 {
	return time.Now().UnixNano()
}

// HealthStore implements Health interface, this stores values in memory.
type HealthStore struct {
	policies       *sync.Map
	bucketDuration int
	buckets        int
	now            func() int64
}

func (h *HealthStore) get(key string) *TimePolicy {
	if v, ok := h.policies.Load(key); ok {
		return v.(*TimePolicy)
	}
	p := NewTimePolicy(make([][]int64, h.buckets), time.Duration(h.bucketDuration)*time.Second)
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
		h.now = nanoTime
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
	count := p.Reduce(countFunc)
	var el int64
	if val != "-1" {
		el, _ = strconv.ParseInt(val, 10, 64)
	} else {
		el = h.now()
	}

	p.Append(el)
	return int(count), nil
}

// CalculateHealthAVG returns the average by counting all items in the buckets
// window divided by their window size.
//
// NOTE:(gernest)  There is no documentation on the redis code. I am just trying
// to replicate similar results here , I have no clue on why are we doing this,
// because meaning metric here is average which we can already calculate.
func (h *HealthStore) CalculateHealthAVG(keyName string, per int64, val string, pipeline bool) (float64, error) {
	p := h.get(keyName)
	count := float64(p.Reduce(countFunc))
	var el int64
	if val != "-1" {
		el, _ = strconv.ParseInt(val, 10, 64)
	} else {
		el = h.now()
	}
	p.Append(el)
	divisor := healthCountsDivisor()
	if count > 0 {
		return roundValue((float64(count) - 1) / divisor), nil
	}
	return count, nil
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

	a := p.Reduce(func(w [][]int64) int64 {
		var count int64
		var total int64
		for _, bucket := range w {
			for _, p := range bucket {
				total += p
				count++
			}
		}
		return total / count
	})
	avg := roundValue(float64(a))
	var el int64
	if val != "-1" {
		el, _ = strconv.ParseInt(val, 10, 64)
	} else {
		el = h.now()
	}
	p.Append(el)
	if avg > 0 {
		return roundValue(avg), nil
	}
	return avg, nil
}

package storage

import (
	"strconv"
	"sync"
	"time"

	"github.com/asecurityteam/rolling"
)

var _ Health = (*HealthStore)(nil)

// NewHalthStore returns a new HealthStore instance with duration in seconds
func NewHalthStore(duration int) *HealthStore {
	return &HealthStore{
		bucketDuration: duration,
		buckets:        duration,
		policies:       new(sync.Map),
	}
}

// HealthStore implements Health interface, this stores values in memory.
type HealthStore struct {
	policies       *sync.Map
	bucketDuration int
	buckets        int
}

func (h *HealthStore) get(key string) *rolling.TimePolicy {
	if v, ok := h.policies.Load(key); ok {
		return v.(*rolling.TimePolicy)
	}
	p := rolling.NewTimePolicy(rolling.NewWindow(h.buckets), time.Duration(h.bucketDuration)*time.Second)
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
	count := appendToPolicy(h.get(key), val)
	return int(count), nil
}

// CalculateHealthAVG returns the average by counting all items in the buckets
// window divided by their window size.
//
// NOTE:(gernest)  There is no documentation on the redis code. I am just trying
// to replicate similar results here , I have no clue on why are we doing this,
// because meaning metric here is average which we can already calculate.
func (h *HealthStore) CalculateHealthAVG(keyName string, per int64, valueOverride string, pipeline bool) (float64, error) {
	p := h.get(keyName)
	count := appendToPolicy(p, valueOverride)
	if count > 0 {
		return roundValue((count - 1) / float64(h.bucketDuration)), nil
	}
	return count, nil
}

// CalculateHealthMicroAVG returns the average by summing all values added in the
// window divided by their total count.
func (h *HealthStore) CalculateHealthMicroAVG(keyName string, per int64, valueOverride string, pipeline bool) (float64, error) {
	p := h.get(keyName)
	appendToPolicy(p, valueOverride)
	avg := p.Reduce(rolling.Avg)
	if avg > 0 {
		return roundValue(avg), nil
	}
	return avg, nil
}

func appendToPolicy(p *rolling.TimePolicy, val string) float64 {
	var el float64
	if val != "-1" {
		el, _ = strconv.ParseFloat(val, 64)
	} else {
		el = float64(time.Now().UnixNano())
	}
	p.Append(el)
	return p.Reduce(rolling.Count)
}

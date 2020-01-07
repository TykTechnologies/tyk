package storage

import (
	"reflect"
	"testing"
	"time"
)

func TestHealthStore(t *testing.T) {
	start, err := time.Parse(time.RFC3339Nano, "2020-01-07T10:34:32.758704+03:00")
	if err != nil {
		t.Fatal(err)
	}
	key := "health-backend"
	t.Run("Redis", func(ts *testing.T) {
		duration := time.Millisecond
		r := &RedisCluster{KeyPrefix: "redis-health-store", now: func() time.Time {
			n := start.Add(duration)
			duration++
			return n
		}}
		r.DeleteAllKeys()
		testHealth(ts, r, key)
	})

	t.Run("InMemory", func(ts *testing.T) {
		r := NewHalthStore(1)
		duration := time.Millisecond
		r.now = func() int64 {
			n := start.Add(duration).UnixNano()
			duration++
			return n
		}
		testHealth(ts, r, key)
	})
}

func testHealth(t *testing.T, r Health, key string) {
	var collect []int
	var counts []int
	for i := 0; i < 60; i++ {
		c, _ := r.SetRollingWindow(key, 1, "-1", false)
		collect = append(collect, c)
		counts = append(counts, i)
	}
	if !reflect.DeepEqual(counts, collect) {
		t.Errorf("expected %#v\n got %#v", counts, collect)
	}
	avg, err := r.CalculateHealthAVG(key, 1, "-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if avg != 0.98 {
		t.Errorf("avarage: expected %#v got %#v", 0.98, avg)
	}
	avg2, err := r.CalculateHealthMicroAVG(key, 1, "-1", false)
	if err != nil {
		t.Fatal(err)
	}

	expect := 6.635426999662603e+16
	if avg2 != expect {
		t.Errorf("avarage2: expected %#v got %#v", expect, avg2)
	}
}

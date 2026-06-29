package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

type countingAnalyticsStore struct {
	*storage.DummyStorage
	getExpCalls int
	setExpCalls int
}

func newCountingAnalyticsStore() *countingAnalyticsStore {
	return &countingAnalyticsStore{DummyStorage: storage.NewDummyStorage()}
}

func (s *countingAnalyticsStore) GetExp(string) (int64, error) {
	s.getExpCalls++
	return -1, nil
}

func (s *countingAnalyticsStore) SetExp(string, int64) error {
	s.setExpCalls++
	return nil
}

func TestRedisPurgerPurgeInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		interval float32
		want     time.Duration
	}{
		{name: "default", want: 10 * time.Second},
		{name: "configured", interval: 2.5, want: 2500 * time.Millisecond},
		{name: "minimum", interval: 0.5, want: time.Second},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gw := &Gateway{}
			gw.SetConfig(config.Config{
				AnalyticsConfig: config.AnalyticsConfigConfig{
					PurgeInterval: tt.interval,
				},
			})

			if got := (RedisPurger{Gw: gw}).purgeInterval(); got != tt.want {
				t.Errorf("RedisPurger.purgeInterval() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRedisPurgerPurgeIntervalWithoutGateway(t *testing.T) {
	t.Parallel()

	if got, want := (RedisPurger{}).purgeInterval(), 10*time.Second; got != want {
		t.Errorf("RedisPurger.purgeInterval() = %s, want %s", got, want)
	}
}

func TestRedisPurgerInitialPurgeDelay(t *testing.T) {
	t.Parallel()

	purger := RedisPurger{}
	if got := purger.initialPurgeDelay(time.Second); got != time.Second {
		t.Errorf("RedisPurger.initialPurgeDelay(time.Second) = %s, want %s", got, time.Second)
	}

	interval := 50 * time.Millisecond
	got := purger.initialPurgeDelay(interval)
	if got != interval {
		t.Errorf("RedisPurger.initialPurgeDelay(%s) = %s, want %s", interval, got, interval)
	}

	interval = 2 * time.Second
	got = purger.initialPurgeDelay(interval)
	if got < 0 || got >= interval {
		t.Errorf("RedisPurger.initialPurgeDelay(%s) = %s, want [0,%s)", interval, got, interval)
	}
}

func TestRedisPurgerPurgeCacheSkipsWhileRedisDisconnected(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	gw := &Gateway{StorageConnectionHandler: storage.NewConnectionHandler(ctx)}
	gw.SetConfig(config.Config{
		AnalyticsConfig: config.AnalyticsConfigConfig{
			StorageExpirationTime: 60,
		},
	})
	store := newCountingAnalyticsStore()

	purger := RedisPurger{Store: store, Gw: gw}
	purger.PurgeCache()

	if store.getExpCalls != 0 {
		t.Errorf("RedisPurger.PurgeCache() GetExp calls = %d, want 0", store.getExpCalls)
	}
	if store.setExpCalls != 0 {
		t.Errorf("RedisPurger.PurgeCache() SetExp calls = %d, want 0", store.setExpCalls)
	}
}

func TestRedisPurgerPurgeCacheSetsExpiryForAnalyticsKeys(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.SetConfig(config.Config{
		AnalyticsConfig: config.AnalyticsConfigConfig{
			StorageExpirationTime: 60,
		},
	})
	store := newCountingAnalyticsStore()

	purger := RedisPurger{Store: store, Gw: gw}
	purger.PurgeCache()

	if store.getExpCalls != 11 {
		t.Errorf("RedisPurger.PurgeCache() GetExp calls = %d, want 11", store.getExpCalls)
	}
	if store.setExpCalls != 11 {
		t.Errorf("RedisPurger.PurgeCache() SetExp calls = %d, want 11", store.setExpCalls)
	}
}

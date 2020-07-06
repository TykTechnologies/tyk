package storage

import (
	"fmt"
	"time"

	"github.com/go-redis/redis"
)

type RateContext struct {
	Limit     int64
	Remaining int64
	Reset     int64
	Reached   bool
}

type Rate struct {
	Period time.Duration
	Limit  int64
}

func (r *RedisCluster) GetRateLimit(key string, rate Rate) (ctx RateContext, err error) {
	if err := r.up(); err != nil {
		return RateContext{}, err
	}
	client := r.singleton()
	onWatch := func(pipe *redis.Tx) error {
		now := time.Now()
		set := pipe.SetNX(key, 1, rate.Period)
		ok, err := set.Result()
		if err != nil {
			return err
		}
		if ok {
			expires := now.Add(rate.Period)
			ctx = GetContextFromState(now, rate, expires, 1)
			return nil
		}
		value := pipe.Incr(key)
		expires := pipe.PTTL(key)
		count, err := value.Result()
		if err != nil {
			return err
		}
		ttl, err := expires.Result()
		if err != nil {
			return err
		}
		if isExpirationRequired(ttl) {
			exp := pipe.Expire(key, rate.Period)
			v, err := exp.Result()
			if err != nil {
				return err
			}
			if !v {
				return fmt.Errorf("Failed to configure expiration for key %q", key)
			}
		}
		expiration := now.Add(rate.Period)
		if ttl > 0 {
			expiration = now.Add(ttl)
		}
		ctx = GetContextFromState(now, rate, expiration, count)
		return nil
	}
	err = client.Watch(onWatch, key)
	return
}

func isExpirationRequired(ttl time.Duration) bool {
	switch ttl {
	case -1 * time.Nanosecond, -1 * time.Millisecond:
		return true
	default:
		return false
	}
}

func GetContextFromState(now time.Time, rate Rate, expiration time.Time, count int64) RateContext {
	limit := rate.Limit
	remaining := int64(0)
	reached := true
	if count <= limit {
		remaining = limit - count
		reached = false
	}

	reset := expiration.Unix()

	return RateContext{
		Limit:     limit,
		Remaining: remaining,
		Reset:     reset,
		Reached:   reached,
	}
}

package rate

import (
	"context"
	"strconv"
	"time"

	redis "github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/storage"
)

type RedisCluster = storage.RedisCluster

type RollingWindow struct {
	redis redis.UniversalClient
}

func NewRollingWindow(redis redis.UniversalClient) *RollingWindow {
	return &RollingWindow{
		redis: redis,
	}
}

func (rw *RollingWindow) StartPeriod(now time.Time, per int64) string {
	period := time.Duration(per) * time.Second
	ts := now.Add(-period).UnixNano()
	return strconv.FormatInt(ts, 10)
}

// Set will append to a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) Set(ctx context.Context, now time.Time, keyName string, per int64, value_override string, pipeline bool) ([]string, error) {
	startPeriod := rw.StartPeriod(now, per)

	var (
		score  = float64(now.UnixNano())
		member = value_override
	)
	if value_override == "-1" {
		member = strconv.FormatInt(int64(now.UnixNano()), 10)
	}

	var zrange *redis.StringSliceCmd

	exec := rw.redis.TxPipelined
	if pipeline {
		exec = rw.redis.Pipelined
	}

	pipeFn := func(pipe redis.Pipeliner) error {
		zset := NewRollingWindowStorage(rw.redis, pipe, keyName)
		zset.ZRemRangeByScore(ctx, "-inf", startPeriod)
		zset.ZAdd(ctx, member, score)
		zrange = zset.ZRangeAll(ctx)
		zset.Expire(ctx, per)
		return nil
	}

	_, err := exec(ctx, pipeFn)
	if err != nil {
		return nil, err
	}

	result, _ := zrange.Result()
	//	result = append(result, member)
	return result, nil
}

// Get will remove part of a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) Get(ctx context.Context, now time.Time, keyName string, per int64, pipeline bool) ([]string, error) {
	startPeriod := rw.StartPeriod(now, per)

	var zrange *redis.StringSliceCmd

	exec := rw.redis.TxPipelined
	if pipeline {
		exec = rw.redis.Pipelined
	}

	pipeFn := func(pipe redis.Pipeliner) error {
		zset := NewRollingWindowStorage(rw.redis, pipe, keyName)
		zset.ZRemRangeByScore(ctx, "-inf", startPeriod)
		zrange = zset.ZRangeAll(ctx)
		return nil
	}

	_, err := exec(ctx, pipeFn)
	if err != nil {
		return nil, err
	}

	return zrange.Result()
}

// Count returns a count of requests made in a time window. This is enough for
// using the count for a rate limiter decision.
func (rw *RollingWindow) Count(ctx context.Context, keyName string, now time.Time, per int64) (int64, error) {
	//	startPeriod := rw.StartPeriod(now, per)

	zset := NewRollingWindowStorage(rw.redis, nil, keyName)
	return zset.ZCard(ctx).Result()
	// return zset.ZCount(ctx, startPeriod, "+inf").Result()
}

// Add adds a member to a ZSET for a given time window.
func (rw *RollingWindow) Add(ctx context.Context, keyName string, now time.Time, per int64) error {
	var (
		member = strconv.FormatInt(int64(now.UnixNano()), 10)
		score  = float64(now.UnixNano())
	)

	zset := NewRollingWindowStorage(rw.redis, nil, keyName)

	return zset.ZAdd(ctx, member, score).Err()
}

func (rw *RollingWindow) GetCount(ctx context.Context, keyName string, now time.Time, per int64) (int64, error) {
	conn := NewRollingWindowStorage(rw.redis, nil, keyName)

	// TODO: key window

	result, err := conn.Get(ctx).Result()
	if err != nil {
		return 0, err
	}

	return strconv.ParseInt(result, 10, 0)
}

func (rw *RollingWindow) Increment(ctx context.Context, keyName string, now time.Time, per int64) error {
	conn := NewRollingWindowStorage(rw.redis, nil, keyName)

	return conn.Increment(ctx).Err()
}

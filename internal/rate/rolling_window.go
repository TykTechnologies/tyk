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

// Set will append to a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) Set(ctx context.Context, now time.Time, keyName string, per int64, value_override string, pipeline bool) ([]string, error) {
	cur := strconv.FormatInt(int64(now.UnixNano()), 10)
	prevPeriod := now.Add(time.Duration(-1*per) * time.Second)
	period := strconv.FormatInt(int64(prevPeriod.UnixNano()), 10)
	expire := time.Duration(per) * time.Second

	element := &redis.Z{
		Score:  float64(now.UnixNano()),
		Member: value_override,
	}
	if value_override == "-1" {
		element.Member = cur
	}

	var zrange *redis.StringSliceCmd

	exec := rw.redis.TxPipelined
	if pipeline {
		exec = rw.redis.Pipelined
	}

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", period)
		zrange = pipe.ZRange(ctx, keyName, 0, -1)
		pipe.ZAdd(ctx, keyName, element)
		pipe.Expire(ctx, keyName, expire)
		return nil
	}

	_, err := exec(ctx, pipeFn)
	if err != nil {
		return nil, err
	}

	result, err := zrange.Result()
	result = append(result, cur)
	return result, err
}

// Get will remove part of a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) Get(ctx context.Context, now time.Time, keyName string, per int64, pipeline bool) ([]string, error) {
	prevPeriod := now.Add(time.Duration(-1*per) * time.Second)
	period := strconv.FormatInt(int64(prevPeriod.UnixNano()), 10)

	var zrange *redis.StringSliceCmd

	exec := rw.redis.TxPipelined
	if pipeline {
		exec = rw.redis.Pipelined
	}

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", period)
		zrange = pipe.ZRange(ctx, keyName, 0, -1)
		return nil
	}

	_, err := exec(ctx, pipeFn)
	if err != nil {
		return nil, err
	}

	return zrange.Result()
}

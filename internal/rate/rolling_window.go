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

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) SetRollingWindow(ctx context.Context, now time.Time, keyName string, per int64, value_override string, pipeline bool) ([]string, error) {
	prevPeriod := now.Add(time.Duration(-1*per) * time.Second)
	period := strconv.Itoa(int(prevPeriod.UnixNano()))
	expire := time.Duration(per) * time.Second

	element := &redis.Z{
		Score:  float64(now.UnixNano()),
		Member: value_override,
	}
	if value_override == "-1" {
		element.Member = strconv.Itoa(int(now.UnixNano()))
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

	return zrange.Result()
}

// GetRollingWindow will remove part of a sorted set in redis and extract a timed window of values.
func (rw *RollingWindow) GetRollingWindow(ctx context.Context, now time.Time, keyName string, per int64, pipeline bool) ([]string, error) {
	prevPeriod := now.Add(time.Duration(-1*per) * time.Second)
	period := strconv.Itoa(int(prevPeriod.UnixNano()))

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

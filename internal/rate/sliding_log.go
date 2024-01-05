package rate

import (
	"context"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/storage"
)

type SlidingLog struct {
	conn     redis.UniversalClient
	pipeline bool
}

func NewSlidingLog(cluster storage.Handler, pipeline bool) (*SlidingLog, error) {
	conn := new(redis.UniversalClient)
	if err := cluster.As(conn); err != nil {
		return nil, err
	}

	return NewSlidingLogRedis(*conn, pipeline), nil
}

func NewSlidingLogRedis(conn redis.UniversalClient, pipeline bool) *SlidingLog {
	return &SlidingLog{
		conn:     conn,
		pipeline: pipeline,
	}
}

// SetCount will trim the rolling window log, add an item and return the count of the items in a window before the add.
func (r *SlidingLog) SetCount(ctx context.Context, keyName string, per int64) (int64, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.IntCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZCard(ctx, keyName)

		element := redis.Z{
			Score: float64(now.UnixNano()),
		}

		element.Member = strconv.Itoa(int(now.UnixNano()))

		pipe.ZAdd(ctx, keyName, &element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	if err := r.pipeliner(ctx, pipeFn); err != nil {
		return 0, err
	}

	return res.Result()
}

// GetCount will trim the rolling window log and return the count of items remaining.
func (r *SlidingLog) GetCount(ctx context.Context, keyName string, per int64) (int64, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.IntCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZCard(ctx, keyName)

		return nil
	}

	if err := r.pipeliner(ctx, pipeFn); err != nil {
		return 0, err
	}

	return res.Result()
}

// Set will append to a sorted set in redis and return the contents of the window as a slice.
func (r *SlidingLog) Set(ctx context.Context, keyName string, per int64) ([]string, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZRange(ctx, keyName, 0, -1)

		element := redis.Z{
			Score: float64(now.UnixNano()),
		}

		element.Member = strconv.Itoa(int(now.UnixNano()))

		pipe.ZAdd(ctx, keyName, &element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	if err := r.pipeliner(ctx, pipeFn); err != nil {
		return nil, err
	}

	return res.Result()
}

// Get will trim the rolling window log and return the contents of the window as a slice.
func (r *SlidingLog) Get(ctx context.Context, keyName string, per int64) ([]string, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZRange(ctx, keyName, 0, -1)

		return nil
	}

	if err := r.pipeliner(ctx, pipeFn); err != nil {
		return nil, err
	}

	return res.Result()
}

func (r *SlidingLog) pipeliner(ctx context.Context, pipeFn func(pipeFn redis.Pipeliner) error) error {
	var err error
	if r.pipeline {
		_, err = r.conn.Pipelined(ctx, pipeFn)
		return err
	}
	_, err = r.conn.TxPipelined(ctx, pipeFn)
	return err
}

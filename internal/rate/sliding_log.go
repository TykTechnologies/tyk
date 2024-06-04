package rate

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/internal/rate/model"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// SlidingLog implements sliding log storage in redis.
type SlidingLog struct {
	conn     redis.UniversalClient
	pipeline bool

	// PipelineFn is exposed for black box tests in the same package.
	PipelineFn func(context.Context, func(redis.Pipeliner) error) error

	// smoothingFn will evaluate the current rate and must return true if
	// the request should be blocked. It's required.
	smoothingFn SmoothingFn
}

// ErrRedisClientProvider is returned if NewSlidingLog isn't passed a valid RedisClientProvider parameter.
var ErrRedisClientProvider = errors.New("Client doesn't implement RedisClientProvider")

// NewSlidingLog creates a new SlidingLog instance with a storage.Handler. In case
// the storage is offline, it's expected to return nil and an error to handle.
func NewSlidingLog(client interface{}, pipeline bool, smoothingFn SmoothingFn) (*SlidingLog, error) {
	cluster, ok := client.(model.RedisClientProvider)
	if !ok {
		return nil, ErrRedisClientProvider
	}

	conn, err := cluster.Client()
	if err != nil {
		return nil, err
	}

	return NewSlidingLogRedis(conn, pipeline, smoothingFn), nil
}

// NewSlidingLogRedis creates a new SlidingLog instance with a redis.UniversalClient.
func NewSlidingLogRedis(conn redis.UniversalClient, pipeline bool, smoothingFn SmoothingFn) *SlidingLog {
	return &SlidingLog{
		conn:        conn,
		pipeline:    pipeline,
		smoothingFn: smoothingFn,
	}
}

// ExecPipeline will run a pipeline function in a pipeline or transaction.
func (r *SlidingLog) ExecPipeline(ctx context.Context, pipeFn func(redis.Pipeliner) error) error {
	if r.PipelineFn != nil {
		return r.PipelineFn(ctx, pipeFn)
	}

	return r.execPipeline(ctx, pipeFn)
}

func (r *SlidingLog) execPipeline(ctx context.Context, pipeFn func(redis.Pipeliner) error) error {
	if r.pipeline {
		_, err := r.conn.Pipelined(ctx, pipeFn)
		return err
	}

	_, err := r.conn.TxPipelined(ctx, pipeFn)
	return err
}

// SetCount returns the number of items in the current sliding log window, before adding a new item.
// The sliding log is trimmed removing older items, and a `per` seconds expiration is set on the complete log.
func (r *SlidingLog) SetCount(ctx context.Context, now time.Time, keyName string, per int64) (int64, error) {
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.IntCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZCard(ctx, keyName)

		element := redis.Z{
			Score:  float64(now.UnixNano()),
			Member: strconv.Itoa(int(now.UnixNano())),
		}

		pipe.ZAdd(ctx, keyName, element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	if err := r.ExecPipeline(ctx, pipeFn); err != nil {
		return 0, err
	}

	return res.Result()
}

// GetCount returns the number of items in the current sliding log window.
// The sliding log is trimmed removing older items.
func (r *SlidingLog) GetCount(ctx context.Context, now time.Time, keyName string, per int64) (int64, error) {
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.IntCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZCard(ctx, keyName)

		return nil
	}

	if err := r.ExecPipeline(ctx, pipeFn); err != nil {
		return 0, err
	}

	return res.Result()
}

// Set returns the items in the current sliding log window, before adding a new item.
// The sliding log is trimmed removing older items, and a `per` seconds expiration is set on the complete log.
func (r *SlidingLog) Set(ctx context.Context, now time.Time, keyName string, per int64) ([]string, error) {
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZRange(ctx, keyName, 0, -1)

		element := redis.Z{
			Score:  float64(now.UnixNano()),
			Member: strconv.Itoa(int(now.UnixNano())),
		}

		pipe.ZAdd(ctx, keyName, element)
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	if err := r.ExecPipeline(ctx, pipeFn); err != nil {
		return nil, err
	}

	return res.Result()
}

// Get returns the items in the current sliding log window.
// The sliding log is trimmed removing older items.
func (r *SlidingLog) Get(ctx context.Context, now time.Time, keyName string, per int64) ([]string, error) {
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	var res *redis.StringSliceCmd

	pipeFn := func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZRange(ctx, keyName, 0, -1)

		return nil
	}

	if err := r.ExecPipeline(ctx, pipeFn); err != nil {
		return nil, err
	}

	return res.Result()
}

// Do will return two values, the first indicates if a request should be blocked, and the second
// returns an error if any occurred. In case an error occurs, the first value will be `true`.
// If there are issues with storage availability for example, requests will be blocked rather
// than let through, as no rate limit can be enforced without storage.
func (r *SlidingLog) Do(ctx context.Context, now time.Time, key string, maxAllowedRate int64, per int64) (bool, error) {
	currentRate, err := r.SetCount(ctx, now, key, per)
	if err != nil {
		return true, err
	}
	return r.smoothingFn(ctx, key, currentRate, maxAllowedRate), err
}

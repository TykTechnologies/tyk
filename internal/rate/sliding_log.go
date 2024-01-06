package rate

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// SlidingLog implements sliding log storage in redis.
type SlidingLog struct {
	conn     redis.UniversalClient
	pipeline bool

	// PipelineFn is exposed for black box tests in the same package.
	PipelineFn func(context.Context, func(redis.Pipeliner) error) error
}

// RedisClientProvider is a hidden storage API, providing us with a redis.UniversalClient.
type RedisClientProvider interface {
	// Client returns the redis.UniversalClient or an error if not available.
	Client() (redis.UniversalClient, error)
}

// ErrRedisClientProvider is returned if NewSlidingLog isn't passed a valid RedisClientProvider parameter.
var ErrRedisClientProvider = errors.New("Client doesn't implement RedisClientProvider")

// NewSlidingLog creates a new SlidingLog instance with a storage.Handler. In case
// the storage is offline, it's expected to return nil and an error to handle.
func NewSlidingLog(client interface{}, pipeline bool) (*SlidingLog, error) {
	cluster, ok := client.(RedisClientProvider)
	if !ok {
		return nil, ErrRedisClientProvider
	}

	conn, err := cluster.Client()
	if err != nil {
		return nil, err
	}

	return NewSlidingLogRedis(conn, pipeline), nil
}

// NewSlidingLogRedis creates a new SlidingLog instance with a redis.UniversalClient.
func NewSlidingLogRedis(conn redis.UniversalClient, pipeline bool) *SlidingLog {
	r := &SlidingLog{
		conn:     conn,
		pipeline: pipeline,
	}
	return r
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

		element := &redis.Z{
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

		element := &redis.Z{
			Score:  float64(now.UnixNano()),
			Member: strconv.Itoa(int(now.UnixNano())),
		}

		element.Member = strconv.Itoa(int(now.UnixNano()))

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

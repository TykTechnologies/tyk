package rate

import (
	"context"
	"embed"
	"errors"
	"strconv"
	"time"

	"github.com/samber/lo"

	"github.com/TykTechnologies/tyk/internal/rate/model"
	"github.com/TykTechnologies/tyk/internal/redis"
)

//go:embed scripts/*.lua
var fs embed.FS

func mustScript(path string) *redis.Script {
	return redis.NewScript(string(lo.Must(fs.ReadFile(path))))
}

var (
	slidingLogAdd = mustScript("scripts/sliding_log_add.lua")
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
	if err := r.ExecPipeline(ctx, func(pipe redis.Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		res = pipe.ZCard(ctx, keyName)

		pipe.ZAdd(ctx, keyName, redis.Z{
			Score:  float64(now.UnixNano()),
			Member: strconv.Itoa(int(now.UnixNano())),
		})

		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)
		return nil
	}); err != nil {
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
func (r *SlidingLog) Do(ctx context.Context, now time.Time, key string, maxAllowed, per int64) (Stats, bool, error) {
	stats, err := r.SetCountScript(ctx, now, key, maxAllowed, per)

	if err != nil {
		return NewEmptyStats(), true, err
	}

	return stats, r.smoothingFn(ctx, key, int64(stats.Count), maxAllowed), err
}

// SetCountScript get current window occupation
// Deprecated is not complete
func (r *SlidingLog) SetCountScript(
	ctx context.Context,
	now time.Time,
	key string,
	maxAllowed, per int64,
) (Stats, error) {

	now = now.Local()
	windowStart := now.Add(time.Second * time.Duration(-1*per))

	cmd := slidingLogAdd.Run(
		ctx, r.conn, []string{key},
		strconv.FormatInt(now.UnixNano(), 10),
		strconv.FormatInt(windowStart.UnixNano(), 10),
		maxAllowed,
		per,
	)

	if cmd.Err() != nil {
		return NewEmptyStats(), cmd.Err()
	}

	res, err := cmd.Slice()
	if err != nil {
		return NewEmptyStats(), err
	}

	count := res[0].(int64)                                  // nolint:errcheck
	remaining := res[1].(int64)                              // nolint:errcheck
	nanoTs, err := strconv.ParseInt(res[2].(string), 10, 64) // nolint:errcheck

	if err != nil {
		return NewEmptyStats(), err
	}

	earliestLog := time.Unix(nanoTs/1e9, nanoTs%1e9).Local()

	nextAvailableSlotAt := earliestLog.Add(time.Duration(per) * time.Second)

	var reset time.Duration
	if remaining > 0 {
		reset = 0
	} else {
		reset = nextAvailableSlotAt.Sub(now)
	}

	if reset < 0 {
		reset = 0
	}

	return Stats{
		Count:     int(count),
		Remaining: int(remaining),
		Limit:     int(maxAllowed),
		Reset:     reset,
	}, nil
}

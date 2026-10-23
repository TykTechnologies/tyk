package rate

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

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
	conn   redis.UniversalClient
	logger logrus.FieldLogger

	// smoothingFn will evaluate the current rate and must return true if
	// the request should be blocked. It's required.
	smoothingFn SmoothingFn
}

// Option configures a SlidingLog.
type Option func(*SlidingLog)

// WithLogger sets the logger. By default nothing is logged.
func WithLogger(logger logrus.FieldLogger) Option {
	return func(r *SlidingLog) {
		r.logger = logger
	}
}

// ErrRedisClientProvider is returned if NewSlidingLog isn't passed a valid RedisClientProvider parameter.
var (
	ErrRedisClientProvider = errors.New("client doesn't implement RedisClientProvider")
	ErrUnexpectedResponse  = errors.New("unexpected response")
)

// NewSlidingLog creates a new SlidingLog instance with a storage.Handler. In case
// the storage is offline, it's expected to return nil and an error to handle.
func NewSlidingLog(client any, smoothingFn SmoothingFn, opts ...Option) (*SlidingLog, error) {
	cluster, ok := client.(model.RedisClientProvider)
	if !ok {
		return nil, ErrRedisClientProvider
	}

	conn, err := cluster.Client()
	if err != nil {
		return nil, err
	}

	return NewSlidingLogRedis(conn, smoothingFn, opts...), nil
}

// NewSlidingLogRedis creates a new SlidingLog instance with a redis.UniversalClient.
func NewSlidingLogRedis(conn redis.UniversalClient, smoothingFn SmoothingFn, opts ...Option) *SlidingLog {
	r := &SlidingLog{
		conn:        conn,
		logger:      discardLogger(),
		smoothingFn: smoothingFn,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Do will return two values, the first indicates if a request should be blocked, and the second
// returns an error if any occurred. In case an error occurs, the first value will be `true`.
// If there are issues with storage availability for example, requests will be blocked rather
// than let through, as no rate limit can be enforced without storage.
func (r *SlidingLog) Do(ctx context.Context, key string, maxAllowed, per int64) (Stats, bool, error) {
	stats, err := r.invokeSlidingLogAdd(ctx, key, maxAllowed, per)

	if err != nil {
		return NewEmptyStats(), true, err
	}

	return stats, r.smoothingFn(ctx, key, int64(stats.Count), maxAllowed), err
}

// invokeSlidingLogAdd records a hit and returns the window occupation before it.
// Time comes from the redis server, so gateways with skewed clocks agree on the window.
func (r *SlidingLog) invokeSlidingLogAdd(ctx context.Context, key string, maxAllowed, per int64) (Stats, error) {
	res, err := slidingLogAdd.Run(ctx, r.conn, []string{key}, maxAllowed, per).Slice()
	if err != nil {
		return NewEmptyStats(), err
	}

	return r.statsFromReply(res, key, maxAllowed, per)
}

// slidingLogAddReply is the result of sliding_log_add.lua.
type slidingLogAddReply struct {
	count        int64
	remaining    int64
	earliestNano int64
	nowNano      int64
	collisions   int64
}

func parseSlidingLogAddReply(res []any) (slidingLogAddReply, error) {
	if len(res) != 5 {
		return slidingLogAddReply{}, fmt.Errorf("%w: %d fields", ErrUnexpectedResponse, len(res))
	}

	var reply slidingLogAddReply
	var errs [5]error

	reply.count, errs[0] = intField(res, 0)
	reply.remaining, errs[1] = intField(res, 1)
	reply.earliestNano, errs[2] = nanoField(res, 2)
	reply.nowNano, errs[3] = nanoField(res, 3)
	reply.collisions, errs[4] = intField(res, 4)

	return reply, errors.Join(errs[:]...)
}

func intField(res []any, i int) (int64, error) {
	v, ok := res[i].(int64)
	if !ok {
		return 0, fmt.Errorf("%w: field %d is %T", ErrUnexpectedResponse, i, res[i])
	}

	return v, nil
}

func nanoField(res []any, i int) (int64, error) {
	str, ok := res[i].(string)
	if !ok {
		return 0, fmt.Errorf("%w: field %d is %T", ErrUnexpectedResponse, i, res[i])
	}

	v, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: field %d: %w", ErrUnexpectedResponse, i, err)
	}

	return v, nil
}

// statsFromReply turns the result of sliding_log_add.lua into Stats.
func (r *SlidingLog) statsFromReply(res []any, key string, maxAllowed, per int64) (Stats, error) {
	reply, err := parseSlidingLogAddReply(res)
	if err != nil {
		return NewEmptyStats(), err
	}

	if reply.collisions > 0 {
		r.logger.
			WithField("key", key).
			WithField("collisions", reply.collisions).
			Debug("sliding log: hits in the same microsecond")
	}

	var reset time.Duration
	if reply.remaining == 0 {
		reset = time.Duration(reply.earliestNano + per*int64(time.Second) - reply.nowNano)
	}

	if reset < 0 {
		reset = 0
	}

	return Stats{
		Count:     int(reply.count),
		Remaining: int(reply.remaining),
		Limit:     int(maxAllowed),
		Reset:     reset,
	}, nil
}

func discardLogger() logrus.FieldLogger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

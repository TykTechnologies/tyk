package rate

import (
	"context"
	"embed"
	"errors"
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
	conn redis.UniversalClient

	// smoothingFn will evaluate the current rate and must return true if
	// the request should be blocked. It's required.
	smoothingFn SmoothingFn
}

// ErrRedisClientProvider is returned if NewSlidingLog isn't passed a valid RedisClientProvider parameter.
var ErrRedisClientProvider = errors.New("Client doesn't implement RedisClientProvider")

// NewSlidingLog creates a new SlidingLog instance with a storage.Handler. In case
// the storage is offline, it's expected to return nil and an error to handle.
func NewSlidingLog(client interface{}, smoothingFn SmoothingFn) (*SlidingLog, error) {
	cluster, ok := client.(model.RedisClientProvider)
	if !ok {
		return nil, ErrRedisClientProvider
	}

	conn, err := cluster.Client()
	if err != nil {
		return nil, err
	}

	return NewSlidingLogRedis(conn, smoothingFn), nil
}

// NewSlidingLogRedis creates a new SlidingLog instance with a redis.UniversalClient.
func NewSlidingLogRedis(conn redis.UniversalClient, smoothingFn SmoothingFn) *SlidingLog {
	return &SlidingLog{
		conn:        conn,
		smoothingFn: smoothingFn,
	}
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
	cmd := slidingLogAdd.Run(ctx, r.conn, []string{key}, maxAllowed, per)
	if cmd.Err() != nil {
		return NewEmptyStats(), cmd.Err()
	}

	res, err := cmd.Slice()
	if err != nil {
		return NewEmptyStats(), err
	}

	count := res[0].(int64)     // nolint:errcheck
	remaining := res[1].(int64) // nolint:errcheck

	earliestNano, err := strconv.ParseInt(res[2].(string), 10, 64) // nolint:errcheck
	if err != nil {
		return NewEmptyStats(), err
	}

	nowNano, err := strconv.ParseInt(res[3].(string), 10, 64) // nolint:errcheck
	if err != nil {
		return NewEmptyStats(), err
	}

	if collisions := res[4].(int64); collisions > 0 { // nolint:errcheck
		logrus.WithField("key", key).WithField("collisions", collisions).Debug("sliding log: hits in the same microsecond")
	}

	var reset time.Duration
	if remaining == 0 {
		reset = time.Duration(earliestNano + per*int64(time.Second) - nowNano)
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

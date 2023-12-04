package rate

import (
	"context"
	"time"

	redis "github.com/go-redis/redis/v8"
)

type RollingWindowStorage struct {
	redis   redis.UniversalClient
	pipe    redis.Pipeliner
	keyName string
}

func NewRollingWindowStorage(redis redis.UniversalClient, pipe redis.Pipeliner, keyName string) *RollingWindowStorage {
	return &RollingWindowStorage{
		redis:   redis,
		pipe:    pipe,
		keyName: keyName,
	}
}

func (s *RollingWindowStorage) ZCount(ctx context.Context, min, max string) *redis.IntCmd {
	return s.redis.ZCount(ctx, s.keyName, min, max)
}

func (s *RollingWindowStorage) ZRemRangeByScore(ctx context.Context, min, max string) *redis.IntCmd {
	return s.pipe.ZRemRangeByScore(ctx, s.keyName, min, max)
}

func (s *RollingWindowStorage) ZRangeAll(ctx context.Context) *redis.StringSliceCmd {
	return s.pipe.ZRange(ctx, s.keyName, 0, -1)
}

func (s *RollingWindowStorage) Increment(ctx context.Context) *redis.IntCmd {
	return s.redis.Incr(ctx, s.keyName)
}

func (s *RollingWindowStorage) Get(ctx context.Context) *redis.StringCmd {
	return s.redis.Get(ctx, s.keyName)
}

func (s *RollingWindowStorage) ZAdd(ctx context.Context, member string, score float64) *redis.IntCmd {
	value := &redis.Z{
		Member: member,
		Score:  score,
	}
	if s.pipe == nil {
		return s.redis.ZAdd(ctx, s.keyName, value)
	}
	return s.pipe.ZAdd(ctx, s.keyName, value)
}

func (s *RollingWindowStorage) Expire(ctx context.Context, expire int64) *redis.BoolCmd {
	return s.pipe.Expire(ctx, s.keyName, time.Duration(expire)*time.Second)
}

package redis

import (
	redis "github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/storage/internal/model"
)

// Expose the following symbols so we can copy `driver.go` from
// redis6 to redis7 without updating the symbols every time.

type (
	Client        = redis.Client
	ClusterClient = redis.ClusterClient

	Pipeliner = redis.Pipeliner

	UniversalClient  = redis.UniversalClient
	UniversalOptions = redis.UniversalOptions

	StringSliceCmd = redis.StringSliceCmd
	StringCmd      = redis.StringCmd
	ZRangeBy       = redis.ZRangeBy
)

const Nil = redis.Nil

var (
	NewClient         = redis.NewClient
	NewClusterClient  = redis.NewClusterClient
	NewFailoverClient = redis.NewFailoverClient
)

// NewZ is a utility to avoid breaking v8 -> v9 code
func NewZ(member string, score float64) *redis.Z {
	return &redis.Z{
		Member: member,
		Score:  score,
	}
}

// toZS takes a []redis.Z and produces a model.ZS
func toZS(in []redis.Z) model.ZS {
	result := make([]model.Z, 0, len(in))
	for _, item := range in {
		result = append(result, model.Z{
			Member: item.Member,
			Score:  item.Score,
		})
	}
	return model.ZS(result)
}

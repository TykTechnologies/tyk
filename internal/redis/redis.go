// The package redis serves as a refactoring aid. The complete gateway depends
// on this package, and lists the symbols from the upstream dependency in use.
//
// nolint:revive
package redis

import (
	redismock "github.com/go-redis/redismock/v9"
	goredis "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	redis "github.com/redis/go-redis/v9"
)

var (
	NewFailoverClient = redis.NewFailoverClient
	NewClusterClient  = redis.NewClusterClient
	NewClient         = redis.NewClient
	NewClientMock     = redismock.NewClientMock
	NewPool           = goredis.NewPool

	Nil       = redis.Nil
	ErrClosed = redis.ErrClosed
)

type (
	UniversalClient  = redis.UniversalClient
	UniversalOptions = redis.UniversalOptions
	Pipeliner        = redis.Pipeliner

	Client        = redis.Client
	ClusterClient = redis.ClusterClient

	Z            = redis.Z
	ZRangeBy     = redis.ZRangeBy
	ZRangeArgs   = redis.ZRangeArgs
	Message      = redis.Message
	Subscription = redis.Subscription

	IntCmd         = redis.IntCmd
	StringCmd      = redis.StringCmd
	StringSliceCmd = redis.StringSliceCmd
)

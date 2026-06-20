package redis_test

import (
	"errors"
	"reflect"
	"testing"

	redismock "github.com/go-redis/redismock/v9"
	goredis "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	upstreamredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tykredis "github.com/TykTechnologies/tyk/internal/redis"
)

// Verifies: STK-REQ-046, SYS-REQ-134, SW-REQ-121
// MCDC SYS-REQ-134: redis_aliases_available=T => TRUE
// STK-REQ-046:nominal:nominal
// STK-REQ-046:boundary:nominal
// STK-REQ-046:determinism:nominal
// SYS-REQ-134:nominal:nominal
// SYS-REQ-134:boundary:nominal
// SYS-REQ-134:determinism:nominal
// SW-REQ-121:nominal:nominal
// SW-REQ-121:boundary:nominal
// SW-REQ-121:determinism:nominal
//
//mcdc:ignore SYS-REQ-134: redis_aliases_available=F => FALSE -- the onboarded Redis alias package initializes exported aliases at package load time; unavailable aliases would be a compile-time or package-initialization failure rather than a reachable runtime state for this local proof slice [category: defensive] [reviewed: human:buger]
func TestRedisAliasesExposeUpstreamSymbols(t *testing.T) {
	t.Run("constructor aliases preserve upstream function identity", func(t *testing.T) {
		tests := []struct {
			name string
			got  any
			want any
		}{
			{name: "new client", got: tykredis.NewClient, want: upstreamredis.NewClient},
			{name: "new cluster client", got: tykredis.NewClusterClient, want: upstreamredis.NewClusterClient},
			{name: "new failover client", got: tykredis.NewFailoverClient, want: upstreamredis.NewFailoverClient},
			{name: "new client mock", got: tykredis.NewClientMock, want: redismock.NewClientMock},
			{name: "new pool", got: tykredis.NewPool, want: goredis.NewPool},
			{name: "new script", got: tykredis.NewScript, want: upstreamredis.NewScript},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, reflect.ValueOf(tt.want).Pointer(), reflect.ValueOf(tt.got).Pointer())
			})
		}
	})

	t.Run("sentinel errors preserve upstream identity", func(t *testing.T) {
		assert.True(t, errors.Is(tykredis.Nil, upstreamredis.Nil))
		assert.True(t, errors.Is(tykredis.ErrClosed, upstreamredis.ErrClosed))
	})

	t.Run("constructors return upstream-compatible objects without dialing", func(t *testing.T) {
		opts := &tykredis.UniversalOptions{Addrs: []string{"127.0.0.1:6379"}}
		client := tykredis.NewClient(opts.Simple())
		require.NotNil(t, client)
		require.NoError(t, client.Close())

		mockClient, mock := tykredis.NewClientMock()
		require.NotNil(t, mockClient)
		require.NotNil(t, mock)
		require.NoError(t, mockClient.Close())

		script := tykredis.NewScript("return 1")
		require.NotNil(t, script)
	})

	t.Run("representative type aliases remain assignment compatible", func(t *testing.T) {
		var client *tykredis.Client = upstreamredis.NewClient(&upstreamredis.Options{Addr: "127.0.0.1:6379"})
		require.NotNil(t, client)
		require.NoError(t, client.Close())

		var z tykredis.Z = upstreamredis.Z{Score: 1, Member: "member"}
		assert.Equal(t, float64(1), z.Score)
		assert.Equal(t, "member", z.Member)

		var by tykredis.ZRangeBy = upstreamredis.ZRangeBy{Min: "-inf", Max: "+inf"}
		assert.Equal(t, "-inf", by.Min)
		assert.Equal(t, "+inf", by.Max)
	})
}

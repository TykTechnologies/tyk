//go:build integration
// +build integration

package internal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestStorageDrivers(t *testing.T) {
	var testcases = []struct {
		title  string
		config config.StorageOptionsConf
	}{
		{
			title: "Redis <=6 tests",
			config: config.StorageOptionsConf{
				Timeout:   1,
				MaxActive: 10,
				Type:      "redis",
				Host:      "localhost",
				Port:      6379,
			},
		},
		{
			title: "Redis >= 7 tests",
			config: config.StorageOptionsConf{
				Timeout:   1,
				MaxActive: 10,
				Type:      "redis7",
				Host:      "localhost",
				Port:      6380,
			},
		},
	}

	var (
		testKey    = "foobar"
		missingKey = "key-404"
		listKey    = "list-items"
		channelKey = "pubsub-channel-name"
		windowKey  = "rolling-window-key"
	)

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client := New(tc.config)
			defer client.Close()

			// Ping
			err := client.Ping(ctx)
			require.NoError(t, err)

			// FlushAll
			ok, err := client.FlushAll(ctx)
			assert.NoError(t, err)
			assert.True(t, ok)

			t.Run("Get Set Del TTL", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, testKey))
				assert.NoError(t, client.Set(ctx, testKey, "baz", time.Second))

				val, err := client.Get(ctx, missingKey)
				assert.Error(t, err)
				assert.Equal(t, "", val)

				val, err = client.Get(ctx, testKey)
				assert.NoError(t, err)
				assert.Equal(t, "baz", val)

				ttl, err := client.TTL(ctx, testKey)
				assert.NoError(t, err)
				assert.Positive(t, ttl, "ttl should be positive")

				ttl, err = client.TTL(ctx, missingKey)
				assert.NoError(t, err)
				assert.Negative(t, ttl, "ttl for missing key should be negative")
			})

			t.Run("SAdd SRem SIsMember SMembers", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, testKey))

				assert.NoError(t, client.SAdd(ctx, testKey, "baz"))
				assert.NoError(t, client.SAdd(ctx, testKey, "bar"))
				assert.NoError(t, client.SRem(ctx, testKey, "baz"))

				m0, e0 := client.SIsMember(ctx, missingKey, "anything")
				m1, e1 := client.SIsMember(ctx, testKey, "baz")
				m2, e2 := client.SIsMember(ctx, testKey, "bar")

				assert.NoError(t, e0)
				assert.NoError(t, e1)
				assert.NoError(t, e2)

				assert.False(t, m0)
				assert.False(t, m1)
				assert.True(t, m2)

				m, e := client.SMembers(ctx, testKey)
				assert.NoError(t, e)
				assert.Equal(t, []string{"bar"}, m)
			})

			t.Run("Incr Decr", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, testKey))

				c0, e0 := client.Incr(ctx, testKey)
				assert.NoError(t, e0)
				assert.True(t, 1 == c0)

				c1, e1 := client.Incr(ctx, testKey)
				assert.NoError(t, e1)
				assert.True(t, 2 == c1)

				c2, e2 := client.Decr(ctx, testKey)
				assert.NoError(t, e2)
				assert.True(t, 1 == c2)
			})

			t.Run("Exists Keys", func(t *testing.T) {
				c0, e0 := client.Exists(ctx, missingKey)
				c1, e1 := client.Exists(ctx, testKey)

				assert.NoError(t, e0)
				assert.NoError(t, e1)

				assert.True(t, 0 == c0)
				assert.True(t, 1 == c1)

				keys, e := client.GetKeysAndValuesWithFilter(ctx, "foo*")
				assert.NoError(t, e)
				assert.Equal(t, map[string]interface{}{"foobar": "1"}, keys)
			})

			t.Run("DeleteKeys", func(t *testing.T) {
				c, e := client.DeleteKeys(ctx, []string{testKey})
				assert.NoError(t, e)
				assert.True(t, c == 1)
			})

			t.Run("RPushPipelined, RPush, LRange, LRem", func(t *testing.T) {
				// Note: one func takes string, other ...[]byte? Why?
				assert.NoError(t, client.RPush(ctx, listKey, "foo"))
				assert.NoError(t, client.RPushPipelined(ctx, listKey, []byte("bar")))

				v1, e1 := client.LRange(ctx, listKey, 0, -1)
				assert.NoError(t, e1)
				assert.Equal(t, []string{"foo", "bar"}, v1)

				// This requires you read https://redis.io/commands/lrem/
				// to fully understand the parameters.
				v, err := client.LRem(ctx, listKey, 0, "foo")
				assert.NoError(t, err)
				assert.True(t, v == 1)

				vals, err := client.LRangeAndDel(ctx, listKey)
				assert.NoError(t, err)
				assert.Equal(t, []string{"bar"}, vals)
			})

			t.Run("Publish", func(t *testing.T) {
				_, err := client.Publish(ctx, channelKey, "payload")
				assert.NoError(t, err)
			})

			t.Run("ZAdd", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, testKey))

				v1, err := client.ZAdd(ctx, testKey, "slovenia", 100)
				assert.NoError(t, err)
				assert.True(t, v1 == 1)

				v2, err := client.ZAdd(ctx, testKey, "croatia", 50)
				assert.NoError(t, err)
				assert.True(t, v2 == 1)

				c1, err := client.ZRemRangeByScore(ctx, testKey, "0", "70")
				assert.NoError(t, err)
				assert.True(t, c1 == 1)

				z1, err := client.ZRangeByScoreWithScores(ctx, testKey, "0", "1000")
				assert.NoError(t, err)
				assert.Equal(t, z1.Members(), []string{"slovenia"})
				assert.Equal(t, z1.Scores(), []float64{100})

				z1, err = client.ZRangeByScoreWithScores(ctx, testKey, "0", "10")
				assert.NoError(t, err)
				assert.Nil(t, z1.Members())
				assert.Nil(t, z1.Scores())
			})

			t.Run("Expire, DeleteScanMatch", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, testKey))
				assert.NoError(t, client.Set(ctx, testKey, "baz", time.Second))

				keys, err := client.GetKeysAndValuesWithFilter(ctx, "foo*")
				assert.NoError(t, err)
				assert.Len(t, keys, 1)

				val, ok := keys["foobar"].(string)
				assert.Equal(t, "baz", val)
				assert.True(t, ok)

				keys, err = client.GetKeysAndValuesWithFilter(ctx, "bar*")
				assert.NoError(t, err)
				assert.Len(t, keys, 0)

				c1, err := client.DeleteScanMatch(ctx, "foo*")
				assert.NoError(t, err)
				assert.True(t, c1 == 1)

				c1, err = client.DeleteScanMatch(ctx, "foo*")
				assert.NoError(t, err)
				assert.True(t, c1 == 0)

				assert.NoError(t, client.Expire(ctx, testKey, time.Second))
			})

			t.Run("SetRollingWindow", func(t *testing.T) {
				assert.NoError(t, client.Del(ctx, windowKey))

				v1, err := client.SetRollingWindow(ctx, windowKey, 10, "-1", true)
				assert.NoError(t, err)
				assert.Len(t, v1, 0)

				v2a, err := client.GetRollingWindow(ctx, windowKey, 10, true)
				assert.NoError(t, err)

				v2b, err := client.GetRollingWindow(ctx, windowKey, 10, false)
				assert.NoError(t, err)

				assert.Equal(t, v2a, v2b)
				assert.Len(t, v2a, 1)

				v3, err := client.SetRollingWindow(ctx, windowKey, 10, "-1", false)
				assert.NoError(t, err)
				assert.Len(t, v3, 1)
				assert.Equal(t, v3, v2a)
			})

			t.Run("Subscribe", func(t *testing.T) {
				pubsub := client.Subscribe(ctx, "topic")
				pubsub.Close()
			})
		})
	}
}

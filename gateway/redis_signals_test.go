package gateway

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage"
)

// TestPubSubInternals is an unit test for code coverage
func TestPubSubInternals(t *testing.T) {
	gw := &Gateway{}

	message := "from test, expected log output"

	testcases := []struct {
		name   string
		testFn func(*testing.T)
	}{
		{
			name: "test error log, err == nil",
			testFn: func(t *testing.T) {
				t.Helper()
				var err error
				assert.False(t, gw.logPubSubError(err, message))
			},
		},
		{
			name: "test error log, err != nil",
			testFn: func(t *testing.T) {
				t.Helper()
				var err = errors.New("test err")
				assert.True(t, gw.logPubSubError(err, message))
			},
		},
		{
			name: "test add delay",
			testFn: func(t *testing.T) {
				t.Helper()
				gw.addPubSubDelay(time.Microsecond)
				assert.True(t, true)
			},
		},
	}

	for idx, tc := range testcases {
		t.Run(fmt.Sprintf("Test case #%d: %s", idx, tc.name), tc.testFn)
	}
}

func TestPubSubRetryDelay(t *testing.T) {
	t.Run("attempt less than one clamps to minimum", func(t *testing.T) {
		delay := pubSubRetryDelay(0)
		assert.GreaterOrEqual(t, delay, 10*time.Second)
		assert.LessOrEqual(t, delay, 60*time.Second)
	})

	t.Run("delay is capped to 60 seconds", func(t *testing.T) {
		for _, attempt := range []int{4, 8, 16} {
			delay := pubSubRetryDelay(attempt)
			assert.LessOrEqual(t, delay, 60*time.Second)
			assert.GreaterOrEqual(t, delay, 10*time.Second)
		}
	})
}

func TestRedisNotifierBacksOffAfterPublishFailure(t *testing.T) {
	store := &storage.RedisCluster{ConnectionHandler: storage.NewConnectionHandler(context.Background())}
	notifier := &RedisNotifier{
		store:   store,
		channel: "test-channel",
	}

	if notifier.Notify(map[string]string{"message": "first"}) {
		t.Error("RedisNotifier.Notify(redis down) = true, want false")
	}

	if until := notifier.publishBackoffUntil.Load(); until <= time.Now().UnixNano() {
		t.Errorf("RedisNotifier.Notify(redis down) publishBackoffUntil = %d, want future unix nanos", until)
	}

	notifier.store = nil
	if notifier.Notify(map[string]string{"message": "suppressed"}) {
		t.Error("RedisNotifier.Notify(during publish backoff) = true, want false")
	}
}

func TestHandleUserKeyReset(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Setup initial config
	config := ts.Gw.GetConfig()
	oldKey := "old-api-key"
	newKey := "new-api-key"
	config.SlaveOptions.APIKey = oldKey
	ts.Gw.SetConfig(config)

	testCases := []struct {
		name     string
		payload  string
		kvType   string
		kvPath   string
		expected string
	}{
		{
			name:     "Basic key reset",
			payload:  fmt.Sprintf("%s.%s:test", oldKey, newKey),
			expected: newKey,
		},
		{
			name:     "Invalid payload format",
			payload:  "invalid-format",
			expected: oldKey,
		},
		{
			name:     "Wrong key in payload",
			payload:  fmt.Sprintf("wrong-key.%s:test", newKey),
			expected: oldKey,
		},
		{
			name:     "Vault key reset",
			payload:  fmt.Sprintf("%s.%s:test", oldKey, newKey),
			kvType:   "vault",
			kvPath:   "vault://secret/api-key",
			expected: newKey,
		},
		{
			name:     "Consul key reset",
			payload:  fmt.Sprintf("%s.%s:test", oldKey, newKey),
			kvType:   "consul",
			kvPath:   "consul://api-keys/key",
			expected: newKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := ts.Gw.GetConfig()
			config.SlaveOptions.APIKey = oldKey
			if tc.kvPath != "" {
				config.Private.EdgeOriginalAPIKeyPath = tc.kvPath
			}
			ts.Gw.SetConfig(config)

			ts.Gw.handleUserKeyReset(tc.payload)

			updatedConfig := ts.Gw.GetConfig()
			assert.Equal(t, tc.expected, updatedConfig.SlaveOptions.APIKey)
		})
	}
}

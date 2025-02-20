package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPubSubInternals is an unit test for code coverage
func TestPubSubInternals(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

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
				assert.False(t, g.Gw.logPubSubError(err, message))
			},
		},
		{
			name: "test error log, err != nil",
			testFn: func(t *testing.T) {
				t.Helper()
				var err = errors.New("test err")
				assert.True(t, g.Gw.logPubSubError(err, message))
			},
		},
		{
			name: "test add delay",
			testFn: func(t *testing.T) {
				t.Helper()
				g.Gw.addPubSubDelay(time.Microsecond)
				assert.True(t, true)
			},
		},
	}

	for idx, tc := range testcases {
		t.Run(fmt.Sprintf("Test case #%d: %s", idx, tc.name), tc.testFn)
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

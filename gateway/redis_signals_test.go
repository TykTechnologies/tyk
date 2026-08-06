package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kvlib "github.com/TykTechnologies/storage/kv"
	"github.com/TykTechnologies/tyk/config"
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
		{
			name:     "File key reset",
			payload:  fmt.Sprintf("%s.%s:test", oldKey, newKey),
			kvType:   "file",
			kvPath:   "file://api-keys/key",
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

type setCall struct {
	key   string
	value string
}

type recordingSetter struct {
	mu     sync.Mutex
	writes []setCall
	setErr error
}

func (r *recordingSetter) Get(_ context.Context, key string) (string, error) {
	return "", &kvlib.KeyNotFoundError{KeyPath: key}
}

func (r *recordingSetter) Set(_ context.Context, key, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.setErr != nil {
		return r.setErr
	}

	r.writes = append(r.writes, setCall{key: key, value: value})

	return nil
}

func (r *recordingSetter) lastWrite(t *testing.T) setCall {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	require.NotEmpty(t, r.writes, "expected a Set to have been recorded")

	return r.writes[len(r.writes)-1]
}

func (r *recordingSetter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.writes)
}

func installKVSetter(t *testing.T, gw *Gateway, storeName string) *recordingSetter {
	t.Helper()

	rec := &recordingSetter{}
	typ := kvlib.ProviderType("recording_" + storeName)

	installKVRegistry(t, gw,
		map[string]kvlib.StoreConfig{storeName: {Type: typ}},
		map[kvlib.ProviderType]kvlib.ProviderFactory{
			typ: func(_ json.RawMessage) (kvlib.Provider, error) { return rec, nil },
		},
	)

	return rec
}

func captureGatewayLog(t *testing.T) *logrustest.Hook {
	t.Helper()

	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	orig := log
	log = logger
	t.Cleanup(func() { log = orig })

	return hook
}

func hasLevel(hook *logrustest.Hook, level logrus.Level) bool {
	for _, e := range hook.AllEntries() {
		if e.Level == level {
			return true
		}
	}

	return false
}

func TestUpdateKeyInStore_WritesThroughRegistry(t *testing.T) {
	tests := []struct {
		name      string
		storeName string
		keyPath   string
		wantKey   string
		wantValue string
	}{
		{
			name:      "legacy vault ref writes a single-field data map",
			storeName: "vault",
			keyPath:   "vault://secret/tyk-apis.api_key",
			wantKey:   "secret/tyk-apis",
			wantValue: `{"api_key":"NEWKEY"}`,
		},
		{
			name:      "new-syntax vault ref with fragment writes a single-field data map",
			storeName: "vault",
			keyPath:   "kv://vault/secret/tyk-apis#api_key",
			wantKey:   "secret/tyk-apis",
			wantValue: `{"api_key":"NEWKEY"}`,
		},
		{
			name:      "legacy consul ref writes the value verbatim",
			storeName: "consul",
			keyPath:   "consul://tyk-apis/edge_key",
			wantKey:   "tyk-apis/edge_key",
			wantValue: "NEWKEY",
		},
		{
			name:      "new-syntax consul ref writes the value verbatim",
			storeName: "consul",
			keyPath:   "kv://consul/tyk-apis/edge_key",
			wantKey:   "tyk-apis/edge_key",
			wantValue: "NEWKEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, t.Context())
			rec := installKVSetter(t, gw, tt.storeName)

			gw.updateKeyInStore(tt.keyPath, "NEWKEY")

			got := rec.lastWrite(t)
			require.Equal(t, tt.wantKey, got.key)

			if tt.storeName == "vault" {
				require.JSONEq(t, tt.wantValue, got.value)
				return
			}

			require.Equal(t, tt.wantValue, got.value)
		})
	}
}

func TestUpdateKeyInStore_UnknownStoreWarnsAndDoesNotWrite(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	rec := installKVSetter(t, gw, "vault")
	hook := captureGatewayLog(t)

	gw.updateKeyInStore("kv://absent/some/key", "NEWKEY")

	require.Zero(t, rec.count(), "must not write to any store")
	require.True(t, hasLevel(hook, logrus.WarnLevel),
		"an unknown store must warn, never silently drop the rotation")
}

func TestUpdateKeyInStore_NonWritableStoreWarns(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	// fakeKVProvider implements Get but not Setter, so the store is non-writable.
	installFakeKVStores(t, gw, map[string]map[string]string{
		"vault": {"secret/tyk-apis": `{"api_key":"OLD"}`},
	})
	hook := captureGatewayLog(t)

	gw.updateKeyInStore("vault://secret/tyk-apis.api_key", "NEWKEY")

	require.True(t, hasLevel(hook, logrus.WarnLevel),
		"a non-writable store must warn, never silently drop the rotation")
}

func TestUpdateKeyInStore_SetErrorIsLogged(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	rec := installKVSetter(t, gw, "vault")
	rec.setErr = errors.New("backend down")
	hook := captureGatewayLog(t)

	gw.updateKeyInStore("kv://vault/secret/tyk-apis#api_key", "NEWKEY")

	require.True(t, hasLevel(hook, logrus.ErrorLevel),
		"a failed write must be logged at error level")
}

func TestUpdateKeyInStore_MalformedKVReferenceWarns(t *testing.T) {
	gw := NewGateway(config.Config{}, t.Context())
	rec := installKVSetter(t, gw, "vault")
	hook := captureGatewayLog(t)

	gw.updateKeyInStore("kv://no-path-separator", "NEWKEY")

	require.Zero(t, rec.count())
	require.True(t, hasLevel(hook, logrus.WarnLevel),
		"a malformed kv:// reference must warn, not panic or silently drop")
}

func TestUpdateKeyInStore_SilentNoOps(t *testing.T) {
	tests := []struct {
		name    string
		keyPath string
	}{
		{name: "empty keyPath", keyPath: ""},
		{
			// A plain literal api_key is not a KV reference: there is no store to
			// write back to.
			name:    "non-reference literal keyPath",
			keyPath: "just-a-plain-api-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, t.Context())
			rec := installKVSetter(t, gw, "vault")
			hook := captureGatewayLog(t)

			gw.updateKeyInStore(tt.keyPath, "NEWKEY")

			require.Zero(t, rec.count(), "nothing should be written")
			require.False(t, hasLevel(hook, logrus.WarnLevel),
				"a non-reference key is a valid config, not a warning")
			require.False(t, hasLevel(hook, logrus.ErrorLevel))
		})
	}
}

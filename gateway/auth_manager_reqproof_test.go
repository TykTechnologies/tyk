package gateway

import (
	"encoding/base64"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// Verifies: SYS-REQ-141, SW-REQ-179
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-179:nominal:nominal
// SW-REQ-179:boundary:nominal
// SW-REQ-179:determinism:nominal
func TestDefaultSessionManagerStoreExpiryAndListing(t *testing.T) {
	store := storage.NewDummyStorage()
	manager := DefaultSessionManager{}

	manager.Init(store)
	require.Same(t, store, manager.Store())
	manager.Stop()

	require.NoError(t, store.SetKey("session-a", "{}", 0))
	require.NoError(t, store.SetKey("session-b", "{}", 0))
	gotKeys := manager.Sessions("*")
	sort.Strings(gotKeys)
	assert.Equal(t, []string{"session-a", "session-b"}, gotKeys)

	now := time.Now()
	testCases := []struct {
		name    string
		expires int64
		want    bool
	}{
		{name: "zero expiry is ignored", expires: 0, want: false},
		{name: "future expiry remains valid", expires: now.Add(time.Hour).Unix(), want: false},
		{name: "past expiry is expired", expires: now.Add(-time.Hour).Unix(), want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, manager.KeyExpired(&user.SessionState{Expires: tc.expires}))
		})
	}
}

// Verifies: SYS-REQ-141, SW-REQ-179
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:error_handling:nominal
// SYS-REQ-141:encoding_safety:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-179:nominal:nominal
// SW-REQ-179:boundary:nominal
// SW-REQ-179:error_handling:nominal
// SW-REQ-179:encoding_safety:nominal
// SW-REQ-179:determinism:nominal
func TestDefaultSessionManagerUpdateDetailRemoveAndCache(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testCases := []struct {
		name   string
		hashed bool
		key    string
	}{
		{name: "raw key", key: ts.Gw.generateToken("default", "auth-manager-raw")},
		{name: "hashed key", hashed: true, key: storage.HashKey(ts.Gw.generateToken("default", "auth-manager-hashed"), true)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := CreateStandardSession()
			session.OrgID = "default"
			session.Alias = tc.name

			ts.Gw.SessionCache.Set(tc.key, session.Clone(), 60)
			_, found := ts.Gw.SessionCache.Get(tc.key)
			require.True(t, found)

			require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(tc.key, session, 0, tc.hashed))

			_, found = ts.Gw.SessionCache.Get(tc.key)
			assert.False(t, found)

			stored, found := ts.Gw.GlobalSessionManager.SessionDetail("default", tc.key, tc.hashed)
			require.True(t, found)
			assert.Equal(t, "default", stored.OrgID)
			assert.Equal(t, tc.name, stored.Alias)
			assert.Equal(t, tc.key, stored.KeyID)

			ts.Gw.SessionCache.Set(tc.key, session.Clone(), 60)
			removed := ts.Gw.GlobalSessionManager.RemoveSession("default", tc.key, tc.hashed)

			require.True(t, removed)
			_, found = ts.Gw.SessionCache.Get(tc.key)
			assert.False(t, found)
			_, found = ts.Gw.GlobalSessionManager.SessionDetail("default", tc.key, tc.hashed)
			assert.False(t, found)
		})
	}
}

// Verifies: SYS-REQ-141, SW-REQ-179
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-179:nominal:nominal
// SW-REQ-179:boundary:nominal
// SW-REQ-179:determinism:nominal
func TestDefaultSessionManagerResetQuotaAllowanceScopeKeys(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	handler := newCountingStorageHandler()
	manager := DefaultSessionManager{Gw: ts.Gw, store: handler}
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"global":  {},
			"scoped1": {AllowanceScope: "scope-one"},
			"scoped2": {AllowanceScope: "scope-two"},
		},
	}

	manager.ResetQuota("quota-key", session, true)

	assert.Equal(t, 4, handler.deleteRawKeyCount)
	assert.ElementsMatch(t, []string{
		RateLimitKeyPrefix + "quota-key.BLOCKED",
		QuotaKeyPrefix + "quota-key",
		QuotaKeyPrefix + "scope-one-quota-key",
		QuotaKeyPrefix + "scope-two-quota-key",
	}, handler.deletedRawKeys)
}

// Verifies: SYS-REQ-141, SW-REQ-179
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:encoding_safety:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-179:nominal:nominal
// SW-REQ-179:encoding_safety:nominal
// SW-REQ-179:determinism:nominal
func TestDefaultKeyGeneratorLocalTokensAndSecrets(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	generator := DefaultKeyGenerator{Gw: ts.Gw}

	authKey := generator.GenerateAuthKey("default")
	require.NotEmpty(t, authKey)
	assert.Equal(t, "default", storage.TokenOrg(authKey))

	customKey := ts.Gw.generateToken("default", "custom-key")
	assert.Equal(t, "default", storage.TokenOrg(customKey))

	secret := generator.GenerateHMACSecret()
	decoded, err := base64.StdEncoding.DecodeString(secret)

	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

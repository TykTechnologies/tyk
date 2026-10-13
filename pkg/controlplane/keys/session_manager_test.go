package keys

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/storage/mock"
	"github.com/TykTechnologies/tyk/user"
)

func testCfg(c HashConfig) func() HashConfig { return func() HashConfig { return c } }

func TestSessionManager_UpdateSession_writePaths(t *testing.T) {
	// TT-16259: restored sessions are written with SET ... XX, new ones with plain SET.
	cases := []struct {
		name     string
		hashed   bool
		restored bool
		expect   func(store *mock.MockHandler)
	}{
		{"raw new", false, false, func(s *mock.MockHandler) {
			s.EXPECT().SetKey("key", gomock.Any(), int64(7)).Return(nil)
		}},
		{"hashed new", true, false, func(s *mock.MockHandler) {
			s.EXPECT().GetKeyPrefix().Return("apikey-")
			s.EXPECT().SetRawKey("apikey-key", gomock.Any(), int64(7)).Return(nil)
		}},
		{"raw restored", false, true, func(s *mock.MockHandler) {
			s.EXPECT().SetKeyEx("key", gomock.Any(), int64(7)).Return(nil)
		}},
		{"hashed restored", true, true, func(s *mock.MockHandler) {
			s.EXPECT().GetKeyPrefix().Return("apikey-")
			s.EXPECT().SetRawKeyEx("apikey-key", gomock.Any(), int64(7)).Return(nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockHandler(ctrl)
			tc.expect(store)

			var changed []string
			m := NewSessionManager(store, testCfg(HashConfig{HashKeys: true}), func(h string) { changed = append(changed, h) }, nil)

			s := &user.SessionState{}
			if tc.restored {
				s.MarkAsRestored()
			}
			require.NoError(t, m.UpdateSession("key", s, 7, tc.hashed))

			want := "key"
			if !tc.hashed {
				want = storage.HashKey("key", true)
			}
			assert.Equal(t, []string{want}, changed, "change hook receives the key hash")
		})
	}
}

func TestSessionManager_RemoveSession(t *testing.T) {
	t.Run("raw deletes legacy and org-prefixed forms", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := mock.NewMockHandler(ctrl)
		m := NewSessionManager(store, testCfg(HashConfig{HashKeys: true, HashKeyFunction: storage.HashMurmur64}), nil, nil)

		orgPrefixed := m.GenerateToken("org1", "custom")
		store.EXPECT().DeleteKey("custom").Return(false)
		store.EXPECT().DeleteKey(orgPrefixed).Return(true)

		assert.True(t, m.RemoveSession("org1", "custom", false))
	})
	t.Run("hashed deletes by prefix+hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := mock.NewMockHandler(ctrl)
		m := NewSessionManager(store, testCfg(HashConfig{HashKeys: true}), nil, nil)
		store.EXPECT().GetKeyPrefix().Return("apikey-")
		store.EXPECT().DeleteRawKey("apikey-abc").Return(true)
		assert.True(t, m.RemoveSession("org1", "abc", true))
	})
}

func TestSessionManager_ResetQuota(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockHandler(ctrl)
	m := NewSessionManager(store, testCfg(HashConfig{HashKeys: true}), nil, nil)

	session := &user.SessionState{AccessRights: map[string]user.AccessDefinition{
		"a": {AllowanceScope: "scope-a"},
		"b": {},
	}}
	h := storage.HashKey("tok", true)
	store.EXPECT().DeleteRawKeys([]string{
		RateLimitKeyPrefix + h + SentinelRateLimitKeyPostfix,
		QuotaKeyPrefix + h,
		QuotaKeyPrefix + "scope-a-" + h,
	}).Return(true)

	m.ResetQuota("tok", session, false)
}

func TestSessionManager_SessionDetail_fallbacks(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockHandler(ctrl)
	cfg := HashConfig{HashKeys: true, HashKeyFunction: storage.HashMurmur64, HashKeyFunctionFallback: []string{storage.HashMurmur32}}
	m := NewSessionManager(store, testCfg(cfg), nil, logrus.New())

	// "custom" carries no org, so the manager tries the org-prefixed token,
	// the raw key, then one org-prefixed token per fallback algorithm.
	want := []string{
		m.GenerateToken("org1", "custom"),
		"custom",
		m.GenerateToken("org1", "custom", storage.HashMurmur32),
	}
	stored, _ := json.Marshal(user.SessionState{Alias: "found"})
	store.EXPECT().GetMultiKey(want).Return([]string{"", "", string(stored)}, nil)

	s, ok := m.SessionDetail("org1", "custom", false)
	require.True(t, ok)
	assert.Equal(t, "found", s.Alias)
	assert.Equal(t, want[2], s.KeyID, "KeyID is the form that matched")
	assert.True(t, s.IsRestored())
}

func TestSessionManager_SessionDetail_disabledUsernameActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockHandler(ctrl)
	m := NewSessionManager(store, testCfg(HashConfig{HashKeys: true, DisableKeyActionsByUsername: true}), nil, nil)
	store.EXPECT().GetMultiKey([]string{"custom"}).Return([]string{""}, nil)
	_, ok := m.SessionDetail("org1", "custom", false)
	assert.False(t, ok)
}

func TestDeleteRawKeysWithAllowanceScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockHandler(ctrl)
	session := &user.SessionState{AccessRights: map[string]user.AccessDefinition{
		"a": {AllowanceScope: ""},
		"b": {AllowanceScope: "s2"},
		"c": {AllowanceScope: "s3"},
	}}
	store.EXPECT().DeleteRawKey(QuotaKeyPrefix + "s2-k").Return(true)
	store.EXPECT().DeleteRawKey(QuotaKeyPrefix + "s3-k").Return(true)
	DeleteRawKeysWithAllowanceScope(store, session, "k")

	// nil arguments are ignored
	DeleteRawKeysWithAllowanceScope(nil, session, "k")
	DeleteRawKeysWithAllowanceScope(store, nil, "k")
}

func TestObfuscateKey(t *testing.T) {
	assert.Equal(t, "****jkbs", ObfuscateKey("481408ygjkbs", false))
	assert.Equal(t, "481408ygjkbs", ObfuscateKey("481408ygjkbs", true))
	assert.Equal(t, "--", ObfuscateKey("abc", false))
}

func TestKeyExpired(t *testing.T) {
	m := NewSessionManager(nil, nil, nil, nil)
	assert.False(t, m.KeyExpired(&user.SessionState{Expires: 0}))
	assert.False(t, m.KeyExpired(&user.SessionState{Expires: -1}))
	assert.True(t, m.KeyExpired(&user.SessionState{Expires: time.Now().Add(-time.Minute).Unix()}))
	assert.False(t, m.KeyExpired(&user.SessionState{Expires: time.Now().Add(time.Minute).Unix()}))
}

// TestSessionManager_Redis round-trips a session through a real Redis with
// the same store shape the gateway uses (prefix apikey-, hashed keys), and
// asserts the Redis key name and TTL a data-plane gateway would look up.
func TestSessionManager_Redis(t *testing.T) {
	conf, err := config.New()
	require.NoError(t, err)
	conf.Storage.Database = 14

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := storage.NewConnectionHandler(ctx)
	go ch.Connect(ctx, nil, conf)
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if !ch.WaitConnect(waitCtx) {
		t.Skip("redis not available")
	}

	store := &storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: true, ConnectionHandler: ch}
	cfg := HashConfig{HashKeys: true, HashKeyFunction: storage.HashMurmur64}
	m := NewSessionManager(store, testCfg(cfg), nil, nil)
	m.Init(store)

	token := m.GenerateToken("org1", "")
	t.Cleanup(func() { m.RemoveSession("org1", token, false) })

	in := user.NewSessionState()
	in.OrgID = "org1"
	in.Alias = "redis-roundtrip"
	require.NoError(t, m.UpdateSession(token, in, 120, false))

	// the key a worker gateway asks MDCB for
	hashedName := "apikey-" + storage.HashStr(token)
	raw, err := store.GetRawKey(hashedName)
	require.NoError(t, err)
	var stored user.SessionState
	require.NoError(t, json.Unmarshal([]byte(raw), &stored))
	assert.Equal(t, "redis-roundtrip", stored.Alias)

	ttl, err := store.GetExp(token)
	require.NoError(t, err)
	assert.InDelta(t, 120, ttl, 2)

	byHash, ok := m.SessionDetail("org1", storage.HashStr(token), true)
	require.True(t, ok)
	assert.Equal(t, "redis-roundtrip", byHash.Alias)

	assert.True(t, m.RemoveSession("org1", token, false))
	_, ok = m.SessionDetail("org1", token, false)
	assert.False(t, ok)
}

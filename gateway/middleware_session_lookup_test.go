package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/storage/mock"
)

// A miss must query the API's auth store only when it differs from the global
// session store; when they are the same store the second query repeats the first.
func TestCheckSessionAndIdentityForValidKey_AuthStoreLookups(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sharedStore bool
	}{
		{"auth store is the session store", true},
		{"auth store is a separate store", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sessionStore := mock.NewMockHandler(ctrl)
			authStore := sessionStore
			if !tc.sharedStore {
				authStore = mock.NewMockHandler(ctrl)
				authStore.EXPECT().GetMultiKey(gomock.Any()).Return(nil, storage.ErrKeyNotFound).Times(1)
			}
			sessionStore.EXPECT().GetMultiKey(gomock.Any()).Return(nil, storage.ErrKeyNotFound).Times(1)

			gw := &Gateway{}
			gw.SetConfig(config.Config{})
			gw.GlobalSessionManager = &DefaultSessionManager{store: sessionStore, Gw: gw}
			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{APIID: "api", OrgID: "org"},
				AuthManager:   &DefaultSessionManager{store: authStore, Gw: gw},
			}
			spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState = true
			m := &BaseMiddleware{Spec: spec, Gw: gw}

			session, found := m.CheckSessionAndIdentityForValidKey("some-token-kid", httptest.NewRequest("GET", "/", nil))

			assert.False(t, found)
			assert.Equal(t, "some-token-kid", session.KeyID)
		})
	}
}

func TestSameKeyStore(t *testing.T) {
	conn := &storage.ConnectionHandler{}
	store := func(mod func(*storage.RedisCluster)) *storage.RedisCluster {
		s := &storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: true, ConnectionHandler: conn}
		if mod != nil {
			mod(s)
		}
		return s
	}
	base := store(nil)

	assert.True(t, sameKeyStore(base, base), "same object")
	assert.True(t, sameKeyStore(base, store(nil)), "rebuilt on reload, same keys")
	assert.False(t, sameKeyStore(base, store(func(s *storage.RedisCluster) { s.KeyPrefix = "orgkey." })), "other prefix")
	assert.False(t, sameKeyStore(base, store(func(s *storage.RedisCluster) { s.HashKeys = false })), "other hashing")
	assert.False(t, sameKeyStore(base, store(func(s *storage.RedisCluster) { s.ConnectionHandler = &storage.ConnectionHandler{} })), "other connection")
	assert.False(t, sameKeyStore(base, &RPCStorageHandler{KeyPrefix: "apikey-"}), "RPC-backed auth store")
	assert.False(t, sameKeyStore(base, &LDAPStorageHandler{}), "LDAP-backed auth store")
}

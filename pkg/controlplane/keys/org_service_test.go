package keys

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type orgFixture struct {
	svc   *OrgService
	store *memHandler
	cfg   OrgConfig
}

func newOrgFixture(t *testing.T, apis APIInfoProvider, mutate func(c *OrgConfig)) *orgFixture {
	t.Helper()
	cfg := OrgConfig{HashKeys: true}
	if mutate != nil {
		mutate(&cfg)
	}
	// The org store never hashes key names, but the session manager over it
	// uses the global hash config for quota keys, as the gateway does.
	store := newMemHandler(OrgKeyPrefix, false)
	sessions := NewSessionManager(store, func() HashConfig { return HashConfig{HashKeys: cfg.HashKeys, HashKeyFunction: storage.HashMurmur64} }, nil, nil)
	svc := NewOrgService(func() OrgConfig { return cfg }, OrgDeps{
		Resolver: StaticOrgStores{Store: sessions, APIs: apis},
		Default:  sessions,
		Quota:    sessions,
	})
	return &orgFixture{svc: svc, store: store, cfg: cfg}
}

func orgSession() *user.SessionState {
	s := user.NewSessionState()
	s.OrgID = "default"
	s.QuotaMax = 1000
	s.QuotaRenewalRate = 3600
	return s
}

func TestOrgService_lifecycle(t *testing.T) {
	apis := staticAPIs{"api-a": {APIID: "api-a", OrgID: "default"}}
	f := newOrgFixture(t, apis, nil)

	res, err := f.svc.Set("default", orgSession(), false, false)
	require.NoError(t, err)
	assert.Equal(t, "added", res.Action)
	assert.True(t, res.Found)

	raw, err := f.store.GetRawKey("orgkey.default")
	require.NoError(t, err, "org keys are stored unhashed under orgkey.<org>")
	var stored user.SessionState
	require.NoError(t, json.Unmarshal([]byte(raw), &stored))
	assert.Equal(t, int64(1000), stored.QuotaMax)
	assert.Equal(t, int64(0), f.store.ttl["orgkey.default"], "org keys never expire")

	got, err := f.svc.Get("default")
	require.NoError(t, err)
	assert.Equal(t, int64(1000), got.QuotaMax)

	list, err := f.svc.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"default"}, list)

	// update with reset_quota deletes the quota counters
	require.NoError(t, f.store.SetRawKey(QuotaKeyPrefix+storage.HashStr("default"), "5", 0))
	upd := orgSession()
	upd.QuotaMax = 2000
	res, err = f.svc.Set("default", upd, true, true)
	require.NoError(t, err)
	assert.Equal(t, "modified", res.Action)
	_, ok := f.store.data[QuotaKeyPrefix+storage.HashStr("default")]
	assert.False(t, ok, "quota counter removed")

	del, err := f.svc.Delete("default")
	require.NoError(t, err)
	assert.Equal(t, "deleted", del.Action)
	_, err = f.svc.Get("default")
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)
	assert.Equal(t, "Org not found", se.Message)
}

func TestOrgService_noAPIsLoaded(t *testing.T) {
	t.Run("writes fall back to the default store", func(t *testing.T) {
		f := newOrgFixture(t, staticAPIs{}, nil)
		res, err := f.svc.Set("default", orgSession(), false, false)
		require.NoError(t, err)
		assert.False(t, res.Found)
		_, err = f.store.GetRawKey("orgkey.default")
		require.NoError(t, err)

		// reads still report not found, as the gateway does without specs
		_, err = f.svc.Get("default")
		var se *StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusNotFound, se.Code)
		_, err = f.svc.List("")
		require.ErrorAs(t, err, &se)
		assert.Equal(t, "ORG not found", se.Message)
		_, err = f.svc.Delete("default")
		require.ErrorAs(t, err, &se)
	})
	t.Run("writes refused when the default store is suppressed", func(t *testing.T) {
		f := newOrgFixture(t, staticAPIs{}, func(c *OrgConfig) { c.SupressDefaultOrgStore = true })
		_, err := f.svc.Set("default", orgSession(), false, false)
		var se *StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusNotFound, se.Code)
		assert.Equal(t, "No such organisation found in Active API list", se.Message)
	})
}

func TestOrgService_Delete_missing(t *testing.T) {
	f := newOrgFixture(t, staticAPIs{"api-a": {APIID: "api-a", OrgID: "default"}}, nil)
	_, err := f.svc.Delete("default")
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Code)
	assert.Equal(t, "Failed to remove the key", se.Message)
}

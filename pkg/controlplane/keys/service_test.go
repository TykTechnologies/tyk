package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// ---------------------------------------------------------------------------
// fakes: an in-memory key store and a static API provider, so the service is
// exercised with no gateway and no Redis.

type memHandler struct {
	storage.Handler // unimplemented methods panic, which is intended
	mu              sync.Mutex
	data            map[string]string
	ttl             map[string]int64
	prefix          string
	hashKeys        bool
}

func newMemHandler(prefix string, hashKeys bool) *memHandler {
	return &memHandler{data: map[string]string{}, ttl: map[string]int64{}, prefix: prefix, hashKeys: hashKeys}
}

func (m *memHandler) fix(k string) string {
	if m.hashKeys {
		return m.prefix + storage.HashStr(k)
	}
	return m.prefix + k
}
func (m *memHandler) Connect() bool                   { return true }
func (m *memHandler) GetKeyPrefix() string            { return m.prefix }
func (m *memHandler) GetKey(k string) (string, error) { return m.GetRawKey(m.fix(k)) }
func (m *memHandler) GetRawKey(k string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[k]
	if !ok {
		return "", storage.ErrKeyNotFound
	}
	return v, nil
}
func (m *memHandler) GetMultiKey(ks []string) ([]string, error) {
	out := make([]string, len(ks))
	found := false
	for i, k := range ks {
		if v, err := m.GetRawKey(m.fix(k)); err == nil {
			out[i] = v
			found = true
		}
	}
	if !found {
		return nil, storage.ErrKeyNotFound
	}
	return out, nil
}
func (m *memHandler) SetKey(k, v string, ttl int64) error { return m.SetRawKey(m.fix(k), v, ttl) }
func (m *memHandler) SetRawKey(k, v string, ttl int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[k] = v
	m.ttl[k] = ttl
	return nil
}
func (m *memHandler) SetKeyEx(k, v string, ttl int64) error { return m.SetRawKeyEx(m.fix(k), v, ttl) }
func (m *memHandler) SetRawKeyEx(k, v string, ttl int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[k]; !ok {
		return storage.ErrKeyNotFound
	}
	m.data[k] = v
	m.ttl[k] = ttl
	return nil
}
func (m *memHandler) DeleteKey(k string) bool { return m.DeleteRawKey(m.fix(k)) }
func (m *memHandler) DeleteRawKey(k string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[k]
	delete(m.data, k)
	delete(m.ttl, k)
	return ok
}
func (m *memHandler) DeleteRawKeys(ks []string) bool {
	any := false
	for _, k := range ks {
		if m.DeleteRawKey(k) {
			any = true
		}
	}
	return any
}
func (m *memHandler) GetKeys(filter string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.data {
		if strings.HasPrefix(k, m.prefix+filter) {
			out = append(out, strings.TrimPrefix(k, m.prefix))
		}
	}
	sort.Strings(out)
	return out
}

type staticAPIs map[string]APIInfo

func (s staticAPIs) APIByID(id string) (APIInfo, bool) { a, ok := s[id]; return a, ok }
func (s staticAPIs) APIsForOrg(org string) []APIInfo {
	var out []APIInfo
	for _, a := range s {
		if a.OrgID == org {
			out = append(out, a)
		}
	}
	return out
}
func (s staticAPIs) AllAPIs() []APIInfo {
	out := make([]APIInfo, 0, len(s))
	for _, a := range s {
		out = append(out, a)
	}
	return out
}

type fixture struct {
	svc   *Service
	store *memHandler
	cfg   Config
	pols  *model.Policies
}

func newFixture(t *testing.T, mutate func(c *Config)) *fixture {
	t.Helper()
	cfg := Config{
		HashConfig: HashConfig{HashKeys: true, HashKeyFunction: storage.HashMurmur64},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	store := newMemHandler("apikey-", cfg.HashKeys)
	sessions := NewSessionManager(store, func() HashConfig { return cfg.HashConfig }, nil, nil)
	pols := model.NewPolicies()
	pols.Reload(
		user.Policy{ID: "pol-a", OrgID: "default", Active: true, Rate: 100, Per: 60, QuotaMax: 10, QuotaRenewalRate: 3600,
			AccessRights: map[string]user.AccessDefinition{"api-a": {APIID: "api-a"}, "api-b": {APIID: "api-b"}}},
		user.Policy{ID: "pol-trial", OrgID: "default", Active: true, Rate: 1, Per: 1, QuotaMax: -1, KeyExpiresIn: 3600,
			AccessRights: map[string]user.AccessDefinition{"api-a": {APIID: "api-a"}}},
	)
	apis := staticAPIs{
		"api-a": {APIID: "api-a", OrgID: "default", SessionLifetime: 600},
		"api-b": {APIID: "api-b", OrgID: "default", DontSetQuotasOnCreate: true},
		"mcp-1": {APIID: "mcp-1", OrgID: "default", IsMCP: true},
	}
	svc := New(func() Config { return cfg }, Deps{Sessions: sessions, APIs: apis, Policies: pols})
	return &fixture{svc: svc, store: store, cfg: cfg, pols: pols}
}

func session(policies ...string) *user.SessionState {
	s := user.NewSessionState()
	s.OrgID = "default"
	s.Rate = 10
	s.Per = 60
	s.QuotaMax = 100
	s.QuotaRenewalRate = 3600
	s.ApplyPolicies = policies
	s.AccessRights = map[string]user.AccessDefinition{
		"api-a": {APIID: "api-a", Versions: []string{"Default"}},
		"api-b": {APIID: "api-b", Versions: []string{"Default"}},
	}
	return s
}

func tokenID(t *testing.T, key string) string {
	t.Helper()
	id, err := storage.TokenID(key)
	require.NoError(t, err)
	return id
}

func (f *fixture) stored(t *testing.T, key string) (user.SessionState, int64) {
	t.Helper()
	name := "apikey-" + storage.HashStr(key)
	raw, err := f.store.GetRawKey(name)
	require.NoError(t, err, "expected %s in store", name)
	var s user.SessionState
	require.NoError(t, json.Unmarshal([]byte(raw), &s))
	return s, f.store.ttl[name]
}

// ---------------------------------------------------------------------------

func TestService_Create(t *testing.T) {
	f := newFixture(t, nil)

	res, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)
	assert.Equal(t, "added", res.Action)
	assert.Equal(t, "ok", res.Status)
	assert.Equal(t, storage.HashStr(res.Key), res.KeyHash)
	assert.Equal(t, "default", storage.TokenOrg(res.Key))

	s, ttl := f.stored(t, res.Key)
	assert.Equal(t, float64(100), s.Rate, "policy applied")
	assert.Equal(t, int64(10), s.QuotaMax)
	assert.Equal(t, int64(600), ttl, "max session_lifetime over access rights (api-a=600, api-b=0)")
	assert.NotZero(t, s.QuotaRenews, "quota reset by api-a (api-b has DontSetQuotasOnCreate)")
}

func TestService_Create_lifetimeZeroWhenNoAPILoaded(t *testing.T) {
	f := newFixture(t, nil)
	s := session() // no policy: pol-a would grant api-a and give it a lifetime
	s.AccessRights = map[string]user.AccessDefinition{"unknown": {APIID: "unknown"}}
	res, err := f.svc.Create(s)
	require.NoError(t, err)
	_, ttl := f.stored(t, res.Key)
	assert.Equal(t, int64(0), ttl)
}

func TestService_Create_trialPeriod(t *testing.T) {
	f := newFixture(t, nil)
	s := session("pol-trial")
	s.AccessRights = map[string]user.AccessDefinition{"api-a": {APIID: "api-a"}}
	before := time.Now().Unix()
	res, err := f.svc.Create(s)
	require.NoError(t, err)
	stored, _ := f.stored(t, res.Key)
	assert.GreaterOrEqual(t, stored.Expires, before+3600)
}

func TestService_Create_masterKeys(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		f := newFixture(t, nil)
		s := session()
		s.AccessRights = nil
		_, err := f.svc.Create(s)
		var se *StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusBadRequest, se.Code)
		assert.Equal(t, "Failed to create key, keys must have at least one Access Rights record set.", se.Message)
	})
	t.Run("enabled writes once per known API", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.AllowMasterKeys = true })
		s := session()
		s.AccessRights = nil
		res, err := f.svc.Create(s)
		require.NoError(t, err)
		_, ok := f.store.data["apikey-"+storage.HashStr(res.Key)]
		assert.True(t, ok)
	})
}

func TestService_Create_withCertificate(t *testing.T) {
	f := newFixture(t, nil)
	s := session("pol-a")
	s.Certificate = "defaultcert1"
	res, err := f.svc.Create(s)
	require.NoError(t, err)
	assert.Equal(t, "cert1", tokenID(t, res.Key), "key derived from certificate")

	_, err = f.svc.Create(s)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusInternalServerError, se.Code)
	assert.Contains(t, se.Message, "Key with given certificate already found")
}

func TestService_CreateOrUpdate_customAndUpdate(t *testing.T) {
	f := newFixture(t, nil)

	// custom key create
	res, err := f.svc.CreateOrUpdate("custom-key-0001", session("pol-a"), WriteOptions{})
	require.NoError(t, err)
	assert.Equal(t, "added", res.Action)
	assert.Equal(t, "custom-key-0001", tokenID(t, res.Key))
	assert.Equal(t, storage.HashStr(res.Key), res.KeyHash)
	first, _ := f.stored(t, res.Key)

	// update with suppress_reset keeps counters and creation date
	upd := session("pol-a")
	upd.Alias = "updated"
	time.Sleep(1100 * time.Millisecond)
	res2, err := f.svc.CreateOrUpdate(res.Key, upd, WriteOptions{IsPut: true, SuppressReset: true})
	require.NoError(t, err)
	assert.Equal(t, "modified", res2.Action)
	assert.Empty(t, res2.KeyHash, "no key_hash on update")
	second, _ := f.stored(t, res.Key)
	assert.Equal(t, "updated", second.Alias)
	assert.Equal(t, first.QuotaRenews, second.QuotaRenews)
	assert.Equal(t, first.LastUpdated, second.LastUpdated)
	assert.Equal(t, first.DateCreated.Unix(), second.DateCreated.Unix())

	// update by hash
	upd.Alias = "by-hash"
	_, err = f.svc.CreateOrUpdate(res.KeyHash, upd, WriteOptions{IsPut: true, IsHashed: true})
	require.NoError(t, err)
	third, _ := f.stored(t, res.Key)
	assert.Equal(t, "by-hash", third.Alias)

	// update of a missing key
	_, err = f.svc.CreateOrUpdate("nope", session("pol-a"), WriteOptions{IsPut: true})
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)
	assert.Equal(t, "Key is not found", se.Message)
}

func TestService_CreateOrUpdate_minTokenLength(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MinTokenLength = 8 })
	_, err := f.svc.CreateOrUpdate("short", session("pol-a"), WriteOptions{})
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Code)
	assert.Contains(t, se.Message, "min_token_length (8)")
}

func TestService_CreateOrUpdate_basicAuth(t *testing.T) {
	f := newFixture(t, nil)
	s := session("pol-a")
	s.BasicAuthData.Password = "secret123"
	res, err := f.svc.CreateOrUpdate("alice", s, WriteOptions{})
	require.NoError(t, err)
	assert.Empty(t, res.Key, "basic-auth creates blank the key in the response when hashing is on")
	assert.NotEmpty(t, res.KeyHash)
	assert.NotEmpty(t, res.StoredKey)

	stored, _ := f.stored(t, res.StoredKey)
	assert.EqualValues(t, user.HashBCrypt, stored.BasicAuthData.Hash)
	assert.NotEqual(t, "secret123", stored.BasicAuthData.Password)

	// update with the same (hashed) password keeps it; detail blanks it
	det, err := f.svc.Detail(res.StoredKey, "", "default", false)
	require.NoError(t, err)
	assert.Empty(t, det.BasicAuthData.Password)
}

func TestService_CreateOrUpdate_mcpValidation(t *testing.T) {
	f := newFixture(t, nil)
	s := session("pol-a")
	s.AccessRights = map[string]user.AccessDefinition{
		"api-a": {APIID: "api-a", JSONRPCMethods: []user.JSONRPCMethodLimit{{Name: "tools/call"}}},
	}
	_, err := f.svc.CreateOrUpdate("", s, WriteOptions{})
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Code)
	assert.Contains(t, se.Message, "MCP fields can only be configured on MCP Proxies")

	s.AccessRights = map[string]user.AccessDefinition{
		"mcp-1": {APIID: "mcp-1", AllowedURLs: []user.AccessSpec{{URL: "/x", Methods: []string{"GET"}}}},
	}
	_, err = f.svc.CreateOrUpdate("", s, WriteOptions{})
	require.ErrorAs(t, err, &se)
	assert.Contains(t, se.Message, "cannot be configured on MCP Proxies")

	// unknown APIs are skipped
	s.AccessRights = map[string]user.AccessDefinition{
		"unknown": {APIID: "unknown", JSONRPCMethods: []user.JSONRPCMethodLimit{{Name: "tools/call"}}},
	}
	_, err = f.svc.CreateOrUpdate("", s, WriteOptions{})
	require.NoError(t, err)
}

func TestService_Detail_quotaRemaining(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)

	// a data-plane gateway consumed 3 of the 10 quota units
	require.NoError(t, f.store.SetRawKey(QuotaKeyPrefix+res.KeyHash, "3", 0))

	det, err := f.svc.Detail(res.Key, "api-a", "", false)
	require.NoError(t, err)
	assert.Equal(t, int64(7), det.QuotaRemaining)

	byHash, err := f.svc.Detail(res.KeyHash, "", "default", true)
	require.NoError(t, err)
	assert.Equal(t, int64(7), byHash.QuotaRemaining)

	_, err = f.svc.Detail("missing", "", "default", false)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)
	assert.Equal(t, "Key not found", se.Message)
}

func TestService_Detail_byHashRequiresHashing(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.HashKeys = false })
	_, err := f.svc.Detail("x", "", "default", true)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Code)
}

func TestService_List(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.HashKeys = false })
	r1, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)
	// no policy, so the session keeps only the api-b access right
	s2 := session()
	s2.AccessRights = map[string]user.AccessDefinition{"api-b": {APIID: "api-b"}}
	r2, err := f.svc.Create(s2)
	require.NoError(t, err)
	require.NoError(t, f.store.SetRawKey("apikey-"+QuotaKeyPrefix+"x", "1", 0))

	all, err := f.svc.List(context.Background(), "", "", false)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{r1.Key, r2.Key}, all, "quota keys filtered out")

	onlyA, err := f.svc.List(context.Background(), "default", "api-a", false)
	require.NoError(t, err)
	assert.Equal(t, []string{r1.Key}, onlyA)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.svc.List(ctx, "default", "api-a", false)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusGatewayTimeout, se.Code)
}

func TestService_Delete(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)
	require.NoError(t, f.store.SetRawKey(QuotaKeyPrefix+res.KeyHash, "3", 0))

	out, err := f.svc.Delete(res.Key, "default", "", true)
	require.NoError(t, err)
	assert.Equal(t, "deleted", out.Action)
	assert.Equal(t, res.Key, out.Key)
	_, ok := f.store.data["apikey-"+res.KeyHash]
	assert.False(t, ok)
	_, ok = f.store.data[QuotaKeyPrefix+res.KeyHash]
	assert.False(t, ok, "quota counter reset")

	_, err = f.svc.Delete(res.Key, "default", "", true)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)

	// hashed delete, all APIs → nil result
	res2, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)
	out, err = f.svc.DeleteHashed(res2.KeyHash, "default", "-1", false)
	require.NoError(t, err)
	assert.Nil(t, out)
	_, ok = f.store.data["apikey-"+res2.KeyHash]
	assert.False(t, ok)
}

func TestService_Preview(t *testing.T) {
	f := newFixture(t, nil)
	out := f.svc.Preview(session("pol-a"))
	assert.Equal(t, float64(100), out.Rate)
	assert.Empty(t, f.store.data, "nothing persisted")
}

func TestService_ApplyPolicyIDs(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.svc.Create(session("pol-a"))
	require.NoError(t, err)

	out, err := f.svc.ApplyPolicyIDs(res.KeyHash, []string{"pol-trial"})
	require.NoError(t, err)
	assert.Equal(t, "updated", out.Action)
	stored, ttl := f.stored(t, res.Key)
	assert.Equal(t, []string{"pol-trial"}, stored.ApplyPolicies)
	assert.Equal(t, int64(0), ttl, "policy update writes with TTL 0, as the gateway does")

	_, err = f.svc.ApplyPolicyIDs("nope", []string{"pol-a"})
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)
}

func TestService_KeyNameForUsername(t *testing.T) {
	f := newFixture(t, nil)
	assert.Equal(t, "alice", tokenID(t, f.svc.KeyNameForUsername("default", "alice")))

	g := newFixture(t, func(c *Config) { c.DisableKeyActionsByUsername = true })
	assert.Equal(t, "alice", g.svc.KeyNameForUsername("default", "alice"))
}

func TestService_ApplyLifetime(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.ForceGlobalSessionLifetime = true; c.GlobalSessionLifetime = 42 })
	s := session()
	assert.Equal(t, int64(42), f.svc.ApplyLifetime(s))

	g := newFixture(t, nil)
	s.AccessRights = nil
	assert.Equal(t, int64(0), g.svc.ApplyLifetime(s), "no APIs → 0")
	assert.Equal(t, int64(600), g.svc.ApplyLifetime(s, &APIInfo{SessionLifetime: 600}))
}

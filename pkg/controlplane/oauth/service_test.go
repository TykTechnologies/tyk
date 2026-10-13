package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lonelycode/osin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// ---------------------------------------------------------------------------
// in-memory storage.Handler covering what the OAuth storage uses

type memStore struct {
	storage.Handler
	mu     sync.Mutex
	prefix string
	kv     map[string]string
	ttl    map[string]int64
	lists  map[string][]string
	sets   map[string]map[string]struct{}
	zsets  map[string]map[string]float64
}

func newMemStore(prefix string) *memStore {
	return &memStore{prefix: prefix, kv: map[string]string{}, ttl: map[string]int64{}, lists: map[string][]string{}, sets: map[string]map[string]struct{}{}, zsets: map[string]map[string]float64{}}
}

func (m *memStore) fix(k string) string             { return m.prefix + k }
func (m *memStore) Connect() bool                   { return true }
func (m *memStore) GetKeyPrefix() string            { return m.prefix }
func (m *memStore) GetKey(k string) (string, error) { return m.GetRawKey(m.fix(k)) }
func (m *memStore) GetRawKey(k string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.kv[k]
	if !ok {
		return "", storage.ErrKeyNotFound
	}
	return v, nil
}
func (m *memStore) GetMultiKey(ks []string) ([]string, error) {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i], _ = m.GetRawKey(m.fix(k))
	}
	return out, nil
}
func (m *memStore) SetKey(k, v string, ttl int64) error { return m.SetRawKey(m.fix(k), v, ttl) }
func (m *memStore) SetRawKey(k, v string, ttl int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv[k] = v
	m.ttl[k] = ttl
	return nil
}
func (m *memStore) SetKeyEx(k, v string, ttl int64) error { return m.SetRawKeyEx(m.fix(k), v, ttl) }
func (m *memStore) SetRawKeyEx(k, v string, ttl int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kv[k]; !ok {
		return storage.ErrKeyNotFound
	}
	m.kv[k] = v
	m.ttl[k] = ttl
	return nil
}
func (m *memStore) DeleteKey(k string) bool { return m.DeleteRawKey(m.fix(k)) }
func (m *memStore) DeleteRawKey(k string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.kv[k]
	delete(m.kv, k)
	delete(m.zsets, k)
	return ok
}
func (m *memStore) DeleteRawKeys(ks []string) bool {
	any := false
	for _, k := range ks {
		if m.DeleteRawKey(k) {
			any = true
		}
	}
	return any
}
func (m *memStore) GetKeys(filter string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.kv {
		if strings.HasPrefix(k, m.prefix+filter) {
			out = append(out, strings.TrimPrefix(k, m.prefix))
		}
	}
	sort.Strings(out)
	return out
}
func (m *memStore) GetKeysAndValuesWithFilter(filter string) map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.kv {
		if strings.HasPrefix(k, m.prefix+filter) {
			out[strings.TrimPrefix(k, m.prefix)] = v
		}
	}
	return out
}
func (m *memStore) Exists(k string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.lists[m.fix(k)]
	if !ok {
		_, ok = m.kv[m.fix(k)]
	}
	return ok, nil
}
func (m *memStore) AppendToSet(k, v string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists[m.fix(k)] = append(m.lists[m.fix(k)], v)
}
func (m *memStore) RemoveFromList(k, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, it := range m.lists[m.fix(k)] {
		if it != v {
			out = append(out, it)
		}
	}
	m.lists[m.fix(k)] = out
	return nil
}
func (m *memStore) GetListRange(k string, from, to int64) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.lists[m.fix(k)]...), nil
}
func (m *memStore) AddToSet(k, v string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sets[m.fix(k)] == nil {
		m.sets[m.fix(k)] = map[string]struct{}{}
	}
	m.sets[m.fix(k)][v] = struct{}{}
}
func (m *memStore) RemoveFromSet(k, v string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sets[m.fix(k)], v)
}
func (m *memStore) GetSet(k string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	i := 0
	for v := range m.sets[m.fix(k)] {
		out[string(rune('a'+i))] = v
		i++
	}
	return out, nil
}
func (m *memStore) AddToSortedSet(k, v string, score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.zsets[m.fix(k)] == nil {
		m.zsets[m.fix(k)] = map[string]float64{}
	}
	m.zsets[m.fix(k)][v] = score
}
func (m *memStore) GetSortedSetRange(k, from, to string) ([]string, []float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var lo float64 = -1e18
	if from != "-inf" {
		lo = atof(from)
	}
	var hi float64 = 1e18
	if to != "+inf" {
		hi = atof(to)
	}
	var members []string
	for mem := range m.zsets[m.fix(k)] {
		members = append(members, mem)
	}
	sort.Slice(members, func(i, j int) bool { return m.zsets[m.fix(k)][members[i]] < m.zsets[m.fix(k)][members[j]] })
	var outM []string
	var outS []float64
	for _, mem := range members {
		sc := m.zsets[m.fix(k)][mem]
		if sc >= lo && sc <= hi {
			outM = append(outM, mem)
			outS = append(outS, sc)
		}
	}
	return outM, outS, nil
}
func (m *memStore) RemoveSortedSetRange(k, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lo := atof(from)
	hi := atof(to)
	if from == "-inf" {
		lo = -1e18
	}
	if to == "+inf" {
		hi = 1e18
	}
	for mem, sc := range m.zsets[m.fix(k)] {
		if sc >= lo && sc <= hi {
			delete(m.zsets[m.fix(k)], mem)
		}
	}
	return nil
}

func atof(s string) float64 {
	var f float64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		f = f*10 + float64(c-'0')
	}
	return f
}

// ---------------------------------------------------------------------------
// fixture: two OAuth APIs, one plain API, a policy and a resolver that
// builds one Storage per API over the shared memStore (same as Redis).

type staticAPIs map[string]keys.APIInfo

func (s staticAPIs) APIByID(id string) (keys.APIInfo, bool) { a, ok := s[id]; return a, ok }
func (s staticAPIs) APIsForOrg(org string) []keys.APIInfo {
	var out []keys.APIInfo
	for _, a := range s {
		if a.OrgID == org {
			out = append(out, a)
		}
	}
	return out
}
func (s staticAPIs) AllAPIs() []keys.APIInfo {
	out := make([]keys.APIInfo, 0, len(s))
	for _, a := range s {
		out = append(out, a)
	}
	return out
}

type memResolver struct {
	root     *memStore // unprefixed view of "Redis"
	apis     staticAPIs
	sessions keys.SessionStore
	keys     *keys.Service
	cfg      func() Config
	managers map[string]*Manager
}

func (r *memResolver) storeFor(apiID string) *memStore {
	s := newMemStore(APIPrefix(apiID))
	// share the maps so every prefixed view sees the same data
	s.kv, s.ttl, s.lists, s.sets, s.zsets = r.root.kv, r.root.ttl, r.root.lists, r.root.sets, r.root.zsets
	return s
}

func (r *memResolver) ManagerFor(apiID string, _ bool) (*Manager, Resolution) {
	api, ok := r.apis[apiID]
	if !ok {
		return nil, APINotFound
	}
	if m, ok := r.managers[apiID]; ok {
		return m, Found
	}
	st := NewStorage(r.storeFor(apiID), r.storeFor(apiID), r.sessions, api.OrgID, r.cfg, r.keys, nil)
	srv := NewServer(ServerConfigFor(api, r.cfg()), st, r.keys, nil)
	m := &Manager{API: api, Server: srv, Sessions: r.sessions, Keys: r.keys, Cfg: r.cfg}
	r.managers[apiID] = m
	return m, Found
}

func (r *memResolver) StorageFor(apiID string, create bool) (ExtendedOsinStorageInterface, Resolution) {
	m, res := r.ManagerFor(apiID, create)
	if res != Found {
		return nil, res
	}
	return m.Storage(), Found
}

type fixture struct {
	svc  *Service
	root *memStore
	res  *memResolver
	keys *keys.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	cfg := Config{HashKeys: true, OAuthTokenExpire: 3600, OAuthRefreshExpire: 7200, OAuthTokenExpiredRetainPeriod: 300}
	root := newMemStore("")
	apiKeyStore := newMemStore("apikey-")
	apiKeyStore.kv, apiKeyStore.ttl = root.kv, root.ttl
	hashCfg := keys.HashConfig{HashKeys: true, HashKeyFunction: storage.HashMurmur64}
	sessions := keys.NewSessionManager(apiKeyStore, func() keys.HashConfig { return hashCfg }, nil, nil)
	// the apikey- store hashes names; memStore does not, so hash on the way in
	apiKeyStore.prefix = "apikey-"
	hashed := &hashingStore{memStore: apiKeyStore}
	sessions = keys.NewSessionManager(hashed, func() keys.HashConfig { return hashCfg }, nil, nil)

	pols := model.NewPolicies()
	pols.Reload(user.Policy{ID: "pol-oauth", OrgID: "default", Active: true, Rate: 5, Per: 1, QuotaMax: -1,
		AccessRights: map[string]user.AccessDefinition{"oauth-a": {APIID: "oauth-a"}, "oauth-b": {APIID: "oauth-b"}}})
	apis := staticAPIs{
		"oauth-a": {APIID: "oauth-a", OrgID: "default", UseOAuth2: true, OAuth: keys.OAuthMeta{AllowedAccessTypes: []string{"client_credentials", "authorization_code", "refresh_token", "password"}, AllowedAuthorizeTypes: []string{"code", "token"}}},
		"oauth-b": {APIID: "oauth-b", OrgID: "default", UseOAuth2: true, OAuth: keys.OAuthMeta{AllowedAccessTypes: []string{"client_credentials"}, AllowedAuthorizeTypes: []string{"code"}}},
		"plain":   {APIID: "plain", OrgID: "default"},
	}
	ksvc := keys.New(func() keys.Config { return keys.Config{HashConfig: hashCfg} }, keys.Deps{Sessions: sessions, APIs: apis, Policies: pols})
	res := &memResolver{root: root, apis: apis, sessions: sessions, keys: ksvc, cfg: func() Config { return cfg }, managers: map[string]*Manager{}}
	svc := New(func() Config { return cfg }, Deps{Resolver: res, APIs: apis, Policies: pols, NewSecret: func() string { return "generated-secret" }})
	return &fixture{svc: svc, root: root, res: res, keys: ksvc}
}

// hashingStore mirrors RedisCluster{HashKeys:true}: non-raw operations
// hash the key name before prefixing.
type hashingStore struct{ *memStore }

func (h *hashingStore) GetKey(k string) (string, error) {
	return h.memStore.GetRawKey(h.prefix + storage.HashStr(k))
}
func (h *hashingStore) SetKey(k, v string, ttl int64) error {
	return h.memStore.SetRawKey(h.prefix+storage.HashStr(k), v, ttl)
}
func (h *hashingStore) SetKeyEx(k, v string, ttl int64) error {
	return h.memStore.SetRawKeyEx(h.prefix+storage.HashStr(k), v, ttl)
}
func (h *hashingStore) DeleteKey(k string) bool {
	return h.memStore.DeleteRawKey(h.prefix + storage.HashStr(k))
}
func (h *hashingStore) GetMultiKey(ks []string) ([]string, error) {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i], _ = h.memStore.GetRawKey(h.prefix + storage.HashStr(k))
	}
	return out, nil
}

func (f *fixture) has(key string) bool {
	_, ok := f.root.kv[key]
	return ok
}

func formReq(t *testing.T, path string, form url.Values, basicUser, basicPass string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicUser+":"+basicPass)))
	}
	return r
}

func clientReq() ClientRequest {
	return ClientRequest{ClientID: "client-1", ClientSecret: "secret-1", ClientRedirectURI: "http://client.oauth.com", APIID: "oauth-a", PolicyID: "pol-oauth", Description: "d", MetaData: map[string]interface{}{"a": "b"}}
}

// ---------------------------------------------------------------------------

func TestService_CreateClient(t *testing.T) {
	f := newFixture(t)

	out, err := f.svc.CreateClient(clientReq())
	require.NoError(t, err)
	assert.Equal(t, "client-1", out.ClientID)
	assert.Equal(t, "secret-1", out.ClientSecret)
	assert.Empty(t, out.APIID, "response does not echo api_id")

	assert.True(t, f.has(APIPrefix("oauth-a")+PrefixClient+"client-1"), "client stored under oauth-data.<api>.oauth-clientid.<id>")
	assert.Equal(t, []string{PrefixClient + "client-1"}, f.root.lists[APIPrefix("oauth-a")+PrefixClientIndexList+"default"], "org index list")
	assert.Len(t, f.root.sets[APIPrefix("oauth-a")+PrefixClientset+PrefixClient], 1, "cluster client set")

	// generated id and secret
	gen, err := f.svc.CreateClient(ClientRequest{APIID: "oauth-a", PolicyID: "pol-oauth"})
	require.NoError(t, err)
	assert.NotEmpty(t, gen.ClientID)
	assert.Equal(t, "generated-secret", gen.ClientSecret)

	// errors
	_, err = f.svc.CreateClient(ClientRequest{APIID: "nope"})
	var se *keys.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "API doesn't exist", se.Message)
	_, err = f.svc.CreateClient(ClientRequest{APIID: "plain"})
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "API is not OAuth2", se.Message)
}

func TestService_CreateClient_policyFanOut(t *testing.T) {
	f := newFixture(t)
	out, err := f.svc.CreateClient(ClientRequest{ClientID: "fan", ClientSecret: "s", PolicyID: "pol-oauth"})
	require.NoError(t, err)
	assert.Equal(t, "fan", out.ClientID)
	assert.True(t, f.has(APIPrefix("oauth-a")+PrefixClient+"fan"))
	assert.True(t, f.has(APIPrefix("oauth-b")+PrefixClient+"fan"), "client written to every OAuth API in the policy")

	_, err = f.svc.CreateClient(ClientRequest{ClientID: "x", PolicyID: "missing"})
	var se *keys.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "Policy doesn't exist", se.Message)
}

func TestService_ClientLifecycle(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CreateClient(clientReq())
	require.NoError(t, err)

	got, err := f.svc.GetClient("oauth-a", "client-1")
	require.NoError(t, err)
	assert.Equal(t, "d", got.Description)

	list, err := f.svc.ListClients("oauth-a")
	require.NoError(t, err)
	require.Len(t, list, 1)

	upd, err := f.svc.UpdateClient("oauth-a", "client-1", ClientRequest{ClientRedirectURI: "http://new", PolicyID: "pol-oauth", Description: "updated"})
	require.NoError(t, err)
	assert.Equal(t, "updated", upd.Description)
	assert.Equal(t, "secret-1", upd.ClientSecret, "update keeps the secret")

	rot, err := f.svc.RotateClientSecret("oauth-a", "client-1")
	require.NoError(t, err)
	assert.Equal(t, "generated-secret", rot.ClientSecret)

	apis := f.svc.APIsForClient("client-1", "default")
	assert.Equal(t, []string{"oauth-a"}, apis)

	_, err = f.svc.UpdateClient("oauth-a", "client-1", ClientRequest{PolicyID: "missing"})
	var se *keys.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "Policy doesn't exist", se.Message)

	del, err := f.svc.DeleteClient("oauth-a", "client-1")
	require.NoError(t, err)
	assert.Equal(t, "deleted", del.Action)
	assert.False(t, f.has(APIPrefix("oauth-a")+PrefixClient+"client-1"))
	_, err = f.svc.GetClient("oauth-a", "client-1")
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)
}

func TestService_TokenIssuance(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CreateClient(clientReq())
	require.NoError(t, err)

	keyRules, _ := json.Marshal(map[string]interface{}{"org_id": "default", "rate": 3, "per": 1, "quota_max": -1,
		"access_rights": map[string]interface{}{"oauth-a": map[string]interface{}{"api_id": "oauth-a"}}})

	// authorization code, issued by the control plane
	codeForm := url.Values{"response_type": {"code"}, "redirect_uri": {"http://client.oauth.com"}, "client_id": {"client-1"}}
	resp, err := f.svc.Authorize("oauth-a", formReq(t, "/tyk/oauth/authorize-client/", codeForm, "", ""), string(keyRules))
	require.NoError(t, err)
	require.False(t, resp.IsError, resp.StatusText)
	code, _ := resp.Output["code"].(string)
	require.NotEmpty(t, code)
	assert.True(t, f.has(APIPrefix("oauth-a")+PrefixAuth+code), "oauth-authorize.<code> written")

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(RenderResponse(resp), &out))
	assert.Equal(t, code, out["code"])
	assert.Contains(t, out["redirect_to"], "code="+code)

	nextSecond()
	// exchange it
	exch := url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {"http://client.oauth.com"}, "client_id": {"client-1"}, "code": {code}}
	resp, err = f.svc.Token("oauth-a", formReq(t, "/oauth/token/", exch, "client-1", "secret-1"))
	require.NoError(t, err)
	require.False(t, resp.IsError, resp.StatusText)
	access := resp.Output["access_token"].(string)
	refresh := resp.Output["refresh_token"].(string)
	assertTokenStored(t, f, access, refresh, 3)

	nextSecond()
	// implicit token
	implicit := url.Values{"response_type": {"token"}, "redirect_uri": {"http://client.oauth.com"}, "client_id": {"client-1"}, "client_secret": {"secret-1"}}
	resp, err = f.svc.Authorize("oauth-a", formReq(t, "/tyk/oauth/authorize-client/", implicit, "", ""), string(keyRules))
	require.NoError(t, err)
	require.False(t, resp.IsError, resp.StatusText)
	implicitTok := resp.Output["access_token"].(string)
	assertTokenStored(t, f, implicitTok, "", 3)

	nextSecond()
	// client credentials: session comes from the client's policy
	cc := url.Values{"grant_type": {"client_credentials"}}
	resp, err = f.svc.Token("oauth-a", formReq(t, "/oauth/token/", cc, "client-1", "secret-1"))
	require.NoError(t, err)
	require.False(t, resp.IsError, resp.StatusText)
	ccTok := resp.Output["access_token"].(string)
	assertTokenStored(t, f, ccTok, "", 5)

	nextSecond()
	// refresh
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	resp, err = f.svc.Token("oauth-a", formReq(t, "/oauth/token/", rf, "client-1", "secret-1"))
	require.NoError(t, err)
	require.False(t, resp.IsError, resp.StatusText)
	assertTokenStored(t, f, resp.Output["access_token"].(string), resp.Output["refresh_token"].(string), 3)

	// listing and revocation
	tokens, err := f.svc.ClientTokens("oauth-a", "client-1")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tokens), 3)

	require.NoError(t, f.svc.RevokeClientToken("default", "client-1", ccTok, "access_token"))
	assert.False(t, f.has(APIPrefix("oauth-a")+PrefixAccess+storage.HashStr(ccTok)))
	assert.False(t, f.has("apikey-"+storage.HashStr(ccTok)), "session removed on revoke")

	revoked, err := f.svc.RevokeAllClientTokens("default", "client-1", "secret-1")
	require.NoError(t, err)
	assert.NotEmpty(t, revoked)
	_, err = f.svc.RevokeAllClientTokens("default", "client-1", "wrong")
	require.NoError(t, err, "wrong secret is reported per API, not as an error")

	_, err = f.svc.RevokeAllClientTokens("default", "", "x")
	var se *keys.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusUnauthorized, se.Code)
	assert.Equal(t, ErrClientIDEmpty, se.Message)
}

// nextSecond waits for a new wall-clock second: RemoveAccess deletes index
// entries by exact expiry score, so tokens issued in the same second would
// be removed together (existing gateway behaviour, see TestControlPlaneParity).
func nextSecond() {
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(1050 * time.Millisecond)))
}

func assertTokenStored(t *testing.T, f *fixture, access, refresh string, wantRate float64) {
	t.Helper()
	accessKey := APIPrefix("oauth-a") + PrefixAccess + storage.HashStr(access)
	require.True(t, f.has(accessKey), "oauth-access.<hash> written")
	assert.Equal(t, int64(3600), f.root.ttl[accessKey], "access TTL = oauth_token_expire")

	sessionKey := "apikey-" + storage.HashStr(access)
	raw, ok := f.root.kv[sessionKey]
	require.True(t, ok, "apikey-<hash(token)> session written, as data planes read it")
	var sess user.SessionState
	require.NoError(t, json.Unmarshal([]byte(raw), &sess))
	assert.Equal(t, "client-1", sess.OauthClientID)
	assert.Equal(t, wantRate, sess.Rate)
	assert.Greater(t, sess.Expires, time.Now().Unix())

	_, inIndex := f.root.zsets[APIPrefix("oauth-a")+PrefixClientTokens+"client-1"][storage.HashStr(access)]
	assert.True(t, inIndex, "token index entry")

	if refresh != "" {
		rk := APIPrefix("oauth-a") + PrefixRefresh + refresh
		require.True(t, f.has(rk))
		assert.Equal(t, int64(7200), f.root.ttl[rk], "refresh TTL = oauth_refresh_token_expire")
	}
}

func TestService_InvalidateRefresh(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.InvalidateRefresh("", "tok")
	var se *keys.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "Missing parameter api_id", se.Message)

	_, err = f.svc.InvalidateRefresh("nope", "tok")
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusNotFound, se.Code)

	res, err := f.svc.InvalidateRefresh("oauth-a", "tok")
	require.NoError(t, err)
	assert.Equal(t, "deleted", res.Action)
}

func TestServerConfigFor(t *testing.T) {
	cfg := ServerConfigFor(keys.APIInfo{OAuth: keys.OAuthMeta{AllowedAccessTypes: []string{"client_credentials"}, AllowedAuthorizeTypes: []string{"code"}}}, Config{OAuthErrorStatusCode: 401, OAuthRedirectURISeparator: ";"})
	assert.Equal(t, 401, cfg.ErrorStatusCode)
	assert.Equal(t, osin.AllowedAccessType{osin.CLIENT_CREDENTIALS}, cfg.AllowedAccessTypes)
	assert.Equal(t, osin.AllowedAuthorizeType{osin.CODE}, cfg.AllowedAuthorizeTypes)
	assert.Equal(t, ";", cfg.RedirectUriSeparator)
	assert.Equal(t, 403, ServerConfigFor(keys.APIInfo{}, Config{}).ErrorStatusCode)
}

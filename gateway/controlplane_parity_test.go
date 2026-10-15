package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lonelycode/osin"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestControlPlaneParity records what the admin API handlers (keys, org keys,
// OAuth, certificates) write to Redis and return over HTTP, and compares it
// against golden files under testdata/controlplane.
//
// The goldens were generated before the admin logic was extracted into
// pkg/controlplane. Any refactor of those handlers must leave them unchanged,
// because data-plane gateways and MDCB read these Redis entries verbatim.
//
// Regenerate with: UPDATE_CP_GOLDENS=1 go test ./gateway/ -run TestControlPlaneParity
func TestControlPlaneParity(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.HashKeys = true
		c.HashKeyFunction = storage.HashMurmur64
		c.EnableHashedKeysListing = true
		c.Secret = "parity-admin-secret"
		c.Security.PrivateCertificateEncodingSecret = "parity-cert-secret"
		c.OauthTokenExpire = 3600
		c.OauthRefreshExpire = 7200
		c.OauthTokenExpiredRetainPeriod = 300
	})
	defer ts.Close()

	ts.Gw.LoadAPI(
		BuildAPI(func(spec *APISpec) {
			spec.APIID = "api-a"
			spec.OrgID = "default"
			spec.UseKeylessAccess = false
			spec.SessionLifetime = 600
			spec.Proxy.ListenPath = "/api-a/"
		})[0],
		BuildAPI(func(spec *APISpec) {
			spec.APIID = "api-b"
			spec.OrgID = "default"
			spec.UseKeylessAccess = false
			spec.DontSetQuotasOnCreate = true
			spec.Proxy.ListenPath = "/api-b/"
		})[0],
		buildTestOAuthSpec(func(spec *APISpec) {
			spec.Oauth2Meta.AllowedAccessTypes = append(spec.Oauth2Meta.AllowedAccessTypes, osin.PASSWORD)
		}),
	)

	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "pol-a"
		p.QuotaMax = 10
		p.QuotaRenewalRate = 3600
		p.Rate = 100
		p.Per = 60
		p.KeyExpiresIn = 0
		p.AccessRights = map[string]user.AccessDefinition{
			"api-a": {APIID: "api-a"},
			"api-b": {APIID: "api-b"},
		}
	})
	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "pol-trial"
		p.KeyExpiresIn = 3600
		p.AccessRights = map[string]user.AccessDefinition{
			"api-a": {APIID: "api-a"},
		}
	})
	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "pol-oauth"
		p.KeyExpiresIn = 0
		p.AccessRights = map[string]user.AccessDefinition{
			"999999": {APIID: "999999"},
		}
	})

	rc := &storage.RedisCluster{ConnectionHandler: ts.Gw.StorageConnectionHandler}
	cli, err := rc.Client()
	require.NoError(t, err)

	scenarios := []struct {
		name string
		run  func(p *parityRun)
	}{
		{"keys-create", parityKeysCreate},
		{"keys-custom", parityKeysCustom},
		{"keys-basic-auth", parityKeysBasicAuth},
		{"keys-trial-and-preview", parityKeysTrialAndPreview},
		{"org-keys", parityOrgKeys},
		{"oauth", parityOAuth},
		{"certs", parityCerts},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			require.NoError(t, cli.FlushDB(context.Background()).Err())
			p := &parityRun{t: t, ts: ts, cli: cli}
			sc.run(p)
			p.compareOrUpdate(sc.name)
		})
	}
}

// ---------------------------------------------------------------------------
// scenarios

const parityOrg = "default"

func paritySession(policies ...string) *user.SessionState {
	s := user.NewSessionState()
	s.OrgID = parityOrg
	s.Alias = "parity"
	s.Rate = 10
	s.Per = 60
	s.Expires = 0
	s.QuotaMax = 100
	s.QuotaRenewalRate = 3600
	s.QuotaRemaining = 100
	s.Tags = []string{"parity"}
	s.MetaData = map[string]interface{}{"m": "v"}
	s.ApplyPolicies = policies
	s.AccessRights = map[string]user.AccessDefinition{
		"api-a": {APIID: "api-a", APIName: "api-a", Versions: []string{"Default"}},
		"api-b": {APIID: "api-b", APIName: "api-b", Versions: []string{"Default"}},
	}
	return s
}

func parityKeysCreate(p *parityRun) {
	var created apiModifyKeySuccess
	p.doJSON("create", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/create", Data: paritySession("pol-a"), AdminAuth: true, Code: http.StatusOK}, &created)
	p.token("K1", created.Key)
	p.snap("create")

	p.do("detail", test.TestCase{Method: http.MethodGet, Path: "/tyk/keys/" + created.Key, AdminAuth: true, Code: http.StatusOK})
	p.snap("detail")

	upd := paritySession("pol-a")
	upd.Alias = "parity-updated"
	p.do("update", test.TestCase{Method: http.MethodPut, Path: "/tyk/keys/" + created.Key, Data: upd, AdminAuth: true, Code: http.StatusOK})
	p.snap("update")

	upd.Alias = "parity-suppress"
	p.do("update-suppress-reset", test.TestCase{Method: http.MethodPut, Path: "/tyk/keys/" + created.Key, QueryParams: map[string]string{"suppress_reset": "1"}, Data: upd, AdminAuth: true, Code: http.StatusOK})
	p.snap("update-suppress-reset")

	upd.Alias = "parity-hashed"
	p.do("update-by-hash", test.TestCase{Method: http.MethodPut, Path: "/tyk/keys/" + created.KeyHash, QueryParams: map[string]string{"hashed": "true"}, Data: upd, AdminAuth: true, Code: http.StatusOK})
	p.snap("update-by-hash")

	p.do("policy-update", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/policy/" + created.KeyHash, Data: map[string]interface{}{"apply_policies": []string{"pol-trial"}}, AdminAuth: true, Code: http.StatusOK})
	p.snap("policy-update")

	p.do("detail-by-hash", test.TestCase{Method: http.MethodGet, Path: "/tyk/keys/" + created.KeyHash, QueryParams: map[string]string{"hashed": "true"}, AdminAuth: true, Code: http.StatusOK})
	p.snap("detail-by-hash")

	p.do("list", test.TestCase{Method: http.MethodGet, Path: "/tyk/keys/", QueryParams: map[string]string{"filter": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("list")

	p.do("delete", test.TestCase{Method: http.MethodDelete, Path: "/tyk/keys/" + created.Key, AdminAuth: true, Code: http.StatusOK})
	p.snap("delete")
}

func parityKeysCustom(p *parityRun) {
	var created apiModifyKeySuccess
	p.doJSON("create-custom", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/custom-key-0001", QueryParams: map[string]string{"org_id": parityOrg}, Data: paritySession("pol-a"), AdminAuth: true, Code: http.StatusOK}, &created)
	p.snap("create-custom")

	p.do("delete-custom-by-hash", test.TestCase{Method: http.MethodDelete, Path: "/tyk/keys/" + created.KeyHash, QueryParams: map[string]string{"hashed": "true"}, AdminAuth: true, Code: http.StatusOK})
	p.snap("delete-custom-by-hash")
}

func parityKeysBasicAuth(p *parityRun) {
	s := paritySession("pol-a")
	s.BasicAuthData.Password = "secret123"
	p.do("create-basic", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/pwuser", QueryParams: map[string]string{"org_id": parityOrg}, Data: s, AdminAuth: true, Code: http.StatusOK})
	p.snap("create-basic")

	p.do("detail-basic-by-username", test.TestCase{Method: http.MethodGet, Path: "/tyk/keys/pwuser", QueryParams: map[string]string{"username": "true", "org_id": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("detail-basic-by-username")

	s.Alias = "pw-updated"
	p.do("update-basic", test.TestCase{Method: http.MethodPut, Path: "/tyk/keys/pwuser", QueryParams: map[string]string{"username": "true", "org_id": parityOrg}, Data: s, AdminAuth: true, Code: http.StatusOK})
	p.snap("update-basic")

	p.do("delete-basic", test.TestCase{Method: http.MethodDelete, Path: "/tyk/keys/pwuser", QueryParams: map[string]string{"username": "true", "org_id": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("delete-basic")
}

func parityKeysTrialAndPreview(p *parityRun) {
	var created apiModifyKeySuccess
	s := paritySession("pol-trial")
	s.AccessRights = map[string]user.AccessDefinition{"api-a": {APIID: "api-a", Versions: []string{"Default"}}}
	p.doJSON("create-trial", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/create", Data: s, AdminAuth: true, Code: http.StatusOK}, &created)
	p.token("K1", created.Key)
	p.snap("create-trial")

	p.do("preview", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/preview", Data: paritySession("pol-a"), AdminAuth: true, Code: http.StatusOK})
	p.snap("preview")

	noRights := paritySession("pol-a")
	noRights.ApplyPolicies = nil
	noRights.AccessRights = nil
	p.do("create-no-rights-master-keys-disabled", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/create", Data: noRights, AdminAuth: true})
	p.snap("create-no-rights-master-keys-disabled")
}

func parityOrgKeys(p *parityRun) {
	s := paritySession()
	s.AccessRights = nil
	s.QuotaMax = 1000
	p.do("org-create", test.TestCase{Method: http.MethodPost, Path: "/tyk/org/keys/" + parityOrg, Data: s, AdminAuth: true, Code: http.StatusOK})
	p.snap("org-create")

	p.do("org-get", test.TestCase{Method: http.MethodGet, Path: "/tyk/org/keys/" + parityOrg, AdminAuth: true, Code: http.StatusOK})
	p.snap("org-get")

	s.QuotaMax = 2000
	p.do("org-update-reset-quota", test.TestCase{Method: http.MethodPut, Path: "/tyk/org/keys/" + parityOrg, QueryParams: map[string]string{"reset_quota": "1"}, Data: s, AdminAuth: true, Code: http.StatusOK})
	p.snap("org-update-reset-quota")

	p.do("org-list", test.TestCase{Method: http.MethodGet, Path: "/tyk/org/keys/", AdminAuth: true, Code: http.StatusOK})
	p.snap("org-list")

	p.do("org-delete", test.TestCase{Method: http.MethodDelete, Path: "/tyk/org/keys/" + parityOrg, AdminAuth: true, Code: http.StatusOK})
	p.snap("org-delete")
}

const (
	parityOAuthAPI      = "999999"
	parityOAuthListen   = "/APIID/"
	parityOAuthClientID = "client-1"
	parityOAuthSecret   = "secret-1"
	parityOAuthRedirect = "http://client.oauth.com"
)

func parityOAuthKeyRules() string {
	s := paritySession()
	s.AccessRights = map[string]user.AccessDefinition{parityOAuthAPI: {APIID: parityOAuthAPI, Versions: []string{"Default"}}}
	b, _ := json.Marshal(s)
	return string(b)
}

func parityOAuth(p *parityRun) {
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	basic := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(parityOAuthClientID+":"+parityOAuthSecret)),
	}
	tokenPath := parityOAuthListen + "oauth/token/"
	authorizePath := parityOAuthListen + "tyk/oauth/authorize-client/"
	clientPath := "/tyk/oauth/clients/" + parityOAuthAPI + "/" + parityOAuthClientID

	p.do("client-create", test.TestCase{Method: http.MethodPost, Path: "/tyk/oauth/clients/create", AdminAuth: true, Code: http.StatusOK, Data: NewClientRequest{
		ClientID: parityOAuthClientID, ClientSecret: parityOAuthSecret, ClientRedirectURI: parityOAuthRedirect,
		APIID: parityOAuthAPI, PolicyID: "pol-oauth", Description: "parity client", MetaData: map[string]interface{}{"a": "b"},
	}})
	p.snap("client-create")

	p.do("client-update", test.TestCase{Method: http.MethodPut, Path: clientPath, AdminAuth: true, Code: http.StatusOK, Data: NewClientRequest{
		ClientID: parityOAuthClientID, ClientSecret: parityOAuthSecret, ClientRedirectURI: parityOAuthRedirect,
		APIID: parityOAuthAPI, PolicyID: "pol-oauth", Description: "parity client updated", MetaData: map[string]interface{}{"a": "c"},
	}})
	p.snap("client-update")

	p.do("client-list", test.TestCase{Method: http.MethodGet, Path: "/tyk/oauth/clients/" + parityOAuthAPI, AdminAuth: true, Code: http.StatusOK})
	p.snap("client-list")
	p.do("client-get", test.TestCase{Method: http.MethodGet, Path: clientPath, AdminAuth: true, Code: http.StatusOK})
	p.snap("client-get")
	p.do("client-apis", test.TestCase{Method: http.MethodGet, Path: "/tyk/oauth/clients/apis/" + parityOAuthClientID, QueryParams: map[string]string{"orgID": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("client-apis")

	// authorization code issued by the control plane
	codeForm := url.Values{}
	codeForm.Set("response_type", "code")
	codeForm.Set("redirect_uri", parityOAuthRedirect)
	codeForm.Set("client_id", parityOAuthClientID)
	codeForm.Set("key_rules", parityOAuthKeyRules())
	var codeResp map[string]interface{}
	p.doJSON("authorize-code", test.TestCase{Method: http.MethodPost, Path: authorizePath, Data: codeForm.Encode(), Headers: form, AdminAuth: true, Code: http.StatusOK}, &codeResp)
	p.token("CODE1", str(codeResp["code"]))
	p.snap("authorize-code")

	// code exchange
	exch := url.Values{}
	exch.Set("grant_type", "authorization_code")
	exch.Set("redirect_uri", parityOAuthRedirect)
	exch.Set("client_id", parityOAuthClientID)
	exch.Set("code", str(codeResp["code"]))
	p.nextSecond()
	var tok1 map[string]interface{}
	p.doJSON("token-authorization-code", test.TestCase{Method: http.MethodPost, Path: tokenPath, Data: exch.Encode(), Headers: basic, Code: http.StatusOK}, &tok1)
	p.token("A1", str(tok1["access_token"]))
	p.token("R1", str(tok1["refresh_token"]))
	p.snap("token-authorization-code")

	// implicit token issued by the control plane
	implicit := url.Values{}
	implicit.Set("response_type", "token")
	implicit.Set("redirect_uri", parityOAuthRedirect)
	implicit.Set("client_id", parityOAuthClientID)
	implicit.Set("client_secret", parityOAuthSecret)
	implicit.Set("key_rules", parityOAuthKeyRules())
	p.nextSecond()
	var tok2 map[string]interface{}
	p.doJSON("authorize-implicit-token", test.TestCase{Method: http.MethodPost, Path: authorizePath, Data: implicit.Encode(), Headers: form, AdminAuth: true, Code: http.StatusOK}, &tok2)
	p.token("A2", str(tok2["access_token"]))
	p.snap("authorize-implicit-token")

	// client credentials
	cc := url.Values{}
	cc.Set("grant_type", "client_credentials")
	p.nextSecond()
	var tok3 map[string]interface{}
	p.doJSON("token-client-credentials", test.TestCase{Method: http.MethodPost, Path: tokenPath, Data: cc.Encode(), Headers: basic, Code: http.StatusOK}, &tok3)
	p.token("A3", str(tok3["access_token"]))
	p.snap("token-client-credentials")

	// refresh
	rf := url.Values{}
	rf.Set("grant_type", "refresh_token")
	rf.Set("refresh_token", str(tok1["refresh_token"]))
	p.nextSecond()
	var tok4 map[string]interface{}
	p.doJSON("token-refresh", test.TestCase{Method: http.MethodPost, Path: tokenPath, Data: rf.Encode(), Headers: basic, Code: http.StatusOK}, &tok4)
	p.token("A4", str(tok4["access_token"]))
	p.token("R2", str(tok4["refresh_token"]))
	p.snap("token-refresh")

	// password grant against a basic-auth user on the same org
	pwSession := paritySession()
	pwSession.AccessRights = map[string]user.AccessDefinition{parityOAuthAPI: {APIID: parityOAuthAPI, Versions: []string{"Default"}}}
	pwSession.BasicAuthData.Password = "pw-secret"
	p.do("password-user-create", test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/oauthpwuser", QueryParams: map[string]string{"org_id": parityOrg}, Data: pwSession, AdminAuth: true, Code: http.StatusOK})
	pw := url.Values{}
	pw.Set("grant_type", "password")
	pw.Set("username", "oauthpwuser")
	pw.Set("password", "pw-secret")
	p.nextSecond()
	var tok5 map[string]interface{}
	p.doJSON("token-password", test.TestCase{Method: http.MethodPost, Path: tokenPath, Data: pw.Encode(), Headers: basic}, &tok5)
	if at := str(tok5["access_token"]); at != "" {
		p.token("A5", at)
	}
	if rt := str(tok5["refresh_token"]); rt != "" {
		p.token("R3", rt)
	}
	p.snap("token-password")

	p.do("client-tokens", test.TestCase{Method: http.MethodGet, Path: clientPath + "/tokens", AdminAuth: true, Code: http.StatusOK})
	p.snap("client-tokens")

	rev := url.Values{}
	rev.Set("token", str(tok3["access_token"]))
	rev.Set("token_type_hint", "access_token")
	rev.Set("client_id", parityOAuthClientID)
	rev.Set("org_id", parityOrg)
	p.do("revoke-access-token", test.TestCase{Method: http.MethodPost, Path: "/tyk/oauth/revoke", Data: rev.Encode(), Headers: form, AdminAuth: true, Code: http.StatusOK})
	p.snap("revoke-access-token")

	p.do("invalidate-refresh", test.TestCase{Method: http.MethodDelete, Path: "/tyk/oauth/refresh/" + str(tok4["refresh_token"]), QueryParams: map[string]string{"api_id": parityOAuthAPI}, AdminAuth: true, Code: http.StatusOK})
	p.snap("invalidate-refresh")

	revAll := url.Values{}
	revAll.Set("client_id", parityOAuthClientID)
	revAll.Set("client_secret", parityOAuthSecret)
	revAll.Set("org_id", parityOrg)
	p.do("revoke-all", test.TestCase{Method: http.MethodPost, Path: "/tyk/oauth/revoke_all", Data: revAll.Encode(), Headers: form, AdminAuth: true, Code: http.StatusOK})
	p.snap("revoke-all")

	var rotated map[string]interface{}
	p.doJSON("client-rotate", test.TestCase{Method: http.MethodPut, Path: clientPath + "/rotate", AdminAuth: true, Code: http.StatusOK}, &rotated)
	if sec := str(rotated["secret"]); sec != "" {
		p.rewrite(sec, "<SECRET2>")
	}
	p.snap("client-rotate")

	p.do("purge-lapsed", test.TestCase{Method: http.MethodDelete, Path: "/tyk/oauth/tokens", QueryParams: map[string]string{"scope": "lapsed"}, AdminAuth: true, Code: http.StatusOK})
	p.snap("purge-lapsed")

	p.do("client-delete", test.TestCase{Method: http.MethodDelete, Path: clientPath, AdminAuth: true, Code: http.StatusOK})
	p.snap("client-delete")
}

func parityCerts(p *parityRun) {
	pem, err := os.ReadFile(filepath.Join("testdata", "controlplane", "cert.pem"))
	require.NoError(p.t, err)

	var added map[string]interface{}
	p.doJSON("cert-add", test.TestCase{Method: http.MethodPost, Path: "/tyk/certs", QueryParams: map[string]string{"org_id": parityOrg}, Data: pem, AdminAuth: true, Code: http.StatusOK}, &added)
	certID := str(added["id"])
	require.NotEmpty(p.t, certID)
	p.snap("cert-add")

	p.do("cert-list-ids", test.TestCase{Method: http.MethodGet, Path: "/tyk/certs", QueryParams: map[string]string{"org_id": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("cert-list-ids")
	p.do("cert-list-detailed", test.TestCase{Method: http.MethodGet, Path: "/tyk/certs", QueryParams: map[string]string{"org_id": parityOrg, "mode": "detailed"}, AdminAuth: true, Code: http.StatusOK})
	p.snap("cert-list-detailed")
	p.do("cert-get", test.TestCase{Method: http.MethodGet, Path: "/tyk/certs/" + certID, AdminAuth: true, Code: http.StatusOK})
	p.snap("cert-get")
	p.do("cert-delete", test.TestCase{Method: http.MethodDelete, Path: "/tyk/certs/" + certID, QueryParams: map[string]string{"org_id": parityOrg}, AdminAuth: true, Code: http.StatusOK})
	p.snap("cert-delete")
}

// ---------------------------------------------------------------------------
// harness

type parityEntry struct {
	Key   string      `json:"key"`
	Type  string      `json:"type"`
	TTL   int64       `json:"ttl"`
	Value interface{} `json:"value"`
}

type parityStep struct {
	Name   string        `json:"name"`
	Status int           `json:"status"`
	Body   interface{}   `json:"body"`
	Redis  []parityEntry `json:"redis"`
}

type parityRun struct {
	t   *testing.T
	ts  *Test
	cli redis.UniversalClient

	rewrites   [][2]string
	steps      []parityStep
	lastStatus int
	lastBody   []byte
}

// token registers a generated secret (API key, OAuth token, code) so that the
// value and its hash are replaced by stable placeholders in snapshots.
func (p *parityRun) token(label, tok string) {
	require.NotEmpty(p.t, tok, "expected a generated value for %s", label)
	p.rewrite(storage.HashStr(tok), "<"+label+".hash>")
	p.rewrite(tok, "<"+label+">")
}

// nextSecond waits for the wall clock to enter a new second. OAuth tokens are
// indexed in oauth-client-tokens.<client> by their expiry timestamp, and
// RemoveAccess (oauth_manager.go) deletes by exact score, so two tokens issued
// in the same second would be removed together and make the snapshot
// timing-dependent. This is existing gateway behaviour, recorded as is.
func (p *parityRun) nextSecond() {
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(1100 * time.Millisecond)))
}

func (p *parityRun) rewrite(from, to string) {
	p.rewrites = append(p.rewrites, [2]string{from, to})
}

func (p *parityRun) apply(s string) string {
	for _, r := range p.rewrites {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	return s
}

func (p *parityRun) do(name string, tc test.TestCase) []byte {
	p.t.Helper()
	resp, err := p.ts.Run(p.t, tc)
	require.NoError(p.t, err, name)
	body, err := io.ReadAll(resp.Body)
	require.NoError(p.t, err, name)
	_ = resp.Body.Close()
	p.lastStatus = resp.StatusCode
	p.lastBody = body
	return body
}

func (p *parityRun) doJSON(name string, tc test.TestCase, into interface{}) {
	p.t.Helper()
	body := p.do(name, tc)
	require.NoError(p.t, json.Unmarshal(body, into), "%s: %s", name, string(body))
}

func (p *parityRun) snap(name string) {
	p.t.Helper()
	p.steps = append(p.steps, parityStep{
		Name:   name,
		Status: p.lastStatus,
		Body:   p.normaliseValue(string(p.lastBody)),
		Redis:  p.snapshotRedis(),
	})
}

var parityIgnoredPrefixes = []string{
	"version-check-gateway",
	"livenesscheck-",
	"host-checker",
	"analytics-",
	"apihealth.",
	"redis-test-",
}

func (p *parityRun) snapshotRedis() []parityEntry {
	ctx := context.Background()
	var keys []string
	var cursor uint64
	for {
		batch, next, err := p.cli.Scan(ctx, cursor, "*", 1000).Result()
		require.NoError(p.t, err)
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}

	entries := make([]parityEntry, 0, len(keys))
	for _, k := range keys {
		if parityIgnored(k) {
			continue
		}
		e := parityEntry{Key: p.apply(k)}
		e.Type = p.cli.Type(ctx, k).Val()
		ttl := p.cli.TTL(ctx, k).Val()
		if ttl < 0 {
			// go-redis encodes "no expiry" as -1ns and "missing" as -2ns
			e.TTL = int64(ttl)
		} else {
			secs := int64(ttl.Seconds())
			e.TTL = ((secs + 5) / 10) * 10
		}
		switch e.Type {
		case "string":
			e.Value = p.normaliseValue(p.cli.Get(ctx, k).Val())
		case "list":
			items := p.cli.LRange(ctx, k, 0, -1).Val()
			vals := make([]interface{}, 0, len(items))
			for _, it := range items {
				vals = append(vals, p.normaliseValue(it))
			}
			e.Value = vals
		case "set":
			items := p.cli.SMembers(ctx, k).Val()
			sort.Strings(items)
			vals := make([]interface{}, 0, len(items))
			for _, it := range items {
				vals = append(vals, p.normaliseValue(it))
			}
			e.Value = vals
		case "zset":
			items := p.cli.ZRangeWithScores(ctx, k, 0, -1).Val()
			vals := make([]map[string]interface{}, 0, len(items))
			for _, it := range items {
				vals = append(vals, map[string]interface{}{"member": p.normaliseValue(fmt.Sprint(it.Member)), "score": "<ts>"})
			}
			sort.Slice(vals, func(i, j int) bool { return fmt.Sprint(vals[i]["member"]) < fmt.Sprint(vals[j]["member"]) })
			e.Value = vals
		case "hash":
			m := p.cli.HGetAll(ctx, k).Val()
			vals := map[string]interface{}{}
			for hk, hv := range m {
				vals[p.apply(hk)] = p.normaliseValue(hv)
			}
			e.Value = vals
		default:
			e.Value = "<unsupported type " + e.Type + ">"
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

func parityIgnored(key string) bool {
	for _, pfx := range parityIgnoredPrefixes {
		if strings.HasPrefix(key, pfx) {
			return true
		}
	}
	return false
}

var parityPrivateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// normaliseValue applies placeholder rewrites, scrubs timestamps and random
// material (bcrypt hashes, encrypted private keys) and decodes JSON so that
// goldens are stable across runs and readable in diffs.
func (p *parityRun) normaliseValue(raw string) interface{} {
	s := p.apply(raw)
	if strings.Contains(s, "-----BEGIN") {
		return parityPrivateKeyBlock.ReplaceAllString(s, "<private-key>")
	}
	trim := strings.TrimSpace(s)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		var v interface{}
		if err := json.Unmarshal([]byte(trim), &v); err == nil {
			return parityScrub(v, "")
		}
	}
	return s
}

var parityTimestampFields = map[string]bool{
	"date_created": true,
	"last_updated": true,
	"quota_renews": true,
	"last_check":   true,
	"CreatedAt":    true,
	"created_at":   true,
}

func parityScrub(v interface{}, parent string) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			switch {
			case parityTimestampFields[k]:
				x[k] = "<ts>"
			case k == "expires":
				if f, ok := val.(float64); ok && f > 0 {
					x[k] = "<ts>"
				}
			case k == "password" && parent == "basic_auth_data":
				if s, ok := val.(string); ok && s != "" {
					x[k] = "<password-hash>"
				}
			default:
				x[k] = parityScrub(val, k)
			}
		}
		return x
	case []interface{}:
		for i := range x {
			x[i] = parityScrub(x[i], parent)
		}
		return x
	}
	return v
}

func (p *parityRun) compareOrUpdate(name string) {
	p.t.Helper()
	path := filepath.Join("testdata", "controlplane", name+".golden.json")
	got, err := json.MarshalIndent(p.steps, "", "  ")
	require.NoError(p.t, err)
	got = append(got, '\n')

	if os.Getenv("UPDATE_CP_GOLDENS") != "" {
		require.NoError(p.t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(p.t, os.WriteFile(path, got, 0o644))
		p.t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(p.t, err, "missing golden %s; run with UPDATE_CP_GOLDENS=1", path)
	if string(want) != string(got) {
		actual := path + ".actual"
		_ = os.WriteFile(actual, got, 0o644)
		p.t.Fatalf("control-plane parity mismatch for %s; actual output written to %s (diff with: diff %s %s)", name, actual, path, actual)
	}
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

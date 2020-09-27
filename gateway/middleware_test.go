package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
	cache "github.com/pmylund/go-cache"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/user"
)

type mockStore struct {
	SessionHandler
}

var sess = user.SessionState{
	OrgID:       "TestBaseMiddleware_OrgSessionExpiry",
	DataExpires: 110,
}

func (mockStore) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	return sess.Clone(), true
}

func TestBaseMiddleware_OrgSessionExpiry(t *testing.T) {
	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
	}
	v := int64(100)
	ExpiryCache.Set(sess.OrgID, v, cache.DefaultExpiration)

	got := m.OrgSessionExpiry(sess.OrgID)
	if got != v {
		t.Errorf("expected %d got %d", v, got)
	}
	ExpiryCache.Delete(sess.OrgID)
	got = m.OrgSessionExpiry(sess.OrgID)
	if got != sess.DataExpires {
		t.Errorf("expected %d got %d", sess.DataExpires, got)
	}
}

func TestBaseMiddleware_getAuthType(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"authToken": {AuthHeaderName: "h1"},
		"basic":     {AuthHeaderName: "h2"},
		"coprocess": {AuthHeaderName: "h3"},
		"hmac":      {AuthHeaderName: "h4"},
		"jwt":       {AuthHeaderName: "h5"},
		"oauth":     {AuthHeaderName: "h6"},
		"oidc":      {AuthHeaderName: "h7"},
	}

	baseMid := BaseMiddleware{Spec: spec}

	r, _ := http.NewRequest(http.MethodGet, "", nil)
	r.Header.Set("h1", "t1")
	r.Header.Set("h2", "t2")
	r.Header.Set("h3", "t3")
	r.Header.Set("h4", "t4")
	r.Header.Set("h5", "t5")
	r.Header.Set("h6", "t6")
	r.Header.Set("h7", "t7")

	authKey := &AuthKey{BaseMiddleware: baseMid}
	basic := &BasicAuthKeyIsValid{BaseMiddleware: baseMid}
	coprocess := &CoProcessMiddleware{BaseMiddleware: baseMid}
	hmac := &HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid}
	jwt := &JWTMiddleware{BaseMiddleware: baseMid}
	oauth := &Oauth2KeyExists{BaseMiddleware: baseMid}
	oidc := &OpenIDMW{BaseMiddleware: baseMid}

	// test getAuthType
	assert.Equal(t, authTokenType, authKey.getAuthType())
	assert.Equal(t, basicType, basic.getAuthType())
	assert.Equal(t, coprocessType, coprocess.getAuthType())
	assert.Equal(t, hmacType, hmac.getAuthType())
	assert.Equal(t, jwtType, jwt.getAuthType())
	assert.Equal(t, oauthType, oauth.getAuthType())
	assert.Equal(t, oidcType, oidc.getAuthType())

	// test getAuthToken
	getToken := func(authType string, getAuthToken func(authType string, r *http.Request) (string, apidef.AuthConfig)) string {
		token, _ := getAuthToken(authType, r)
		return token
	}

	assert.Equal(t, "t1", getToken(authKey.getAuthType(), authKey.getAuthToken))
	assert.Equal(t, "t2", getToken(basic.getAuthType(), basic.getAuthToken))
	assert.Equal(t, "t3", getToken(coprocess.getAuthType(), coprocess.getAuthToken))
	assert.Equal(t, "t4", getToken(hmac.getAuthType(), hmac.getAuthToken))
	assert.Equal(t, "t5", getToken(jwt.getAuthType(), jwt.getAuthToken))
	assert.Equal(t, "t6", getToken(oauth.getAuthType(), oauth.getAuthToken))
	assert.Equal(t, "t7", getToken(oidc.getAuthType(), oidc.getAuthToken))
}

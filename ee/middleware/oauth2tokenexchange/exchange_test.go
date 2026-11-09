//go:build ee || dev

package oauth2tokenexchange

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

func activePrimitive(audience string) *oas.MCPPrimitive {
	enabled := true
	p := &oas.MCPPrimitive{}
	p.Exchange = &oas.OAuth2Exchange{Enabled: &enabled, Audience: audience}
	return p
}

func TestFindActivePrimitive_ToolLookup(t *testing.T) {
	mw := &oas.Middleware{
		McpTools: oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
	}
	got := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, got)
	assert.Equal(t, "https://tool-api", got.Exchange.Audience)
}

func TestFindActivePrimitive_PromptLookup(t *testing.T) {
	mw := &oas.Middleware{
		McpPrompts: oas.MCPPrimitives{"search": activePrimitive("https://prompt-api")},
	}
	got := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	require.NotNil(t, got)
	assert.Equal(t, "https://prompt-api", got.Exchange.Audience)
}

// TestFindActivePrimitive_SameNameCollision is the regression guard for the bug
// Andrei identified: a tool and a prompt sharing the same name must not collide.
// Querying by type "prompt" must return nil when only the tool has active exchange.
func TestFindActivePrimitive_SameNameCollision(t *testing.T) {
	mw := &oas.Middleware{
		McpTools:   oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
		McpPrompts: oas.MCPPrimitives{"search": &oas.MCPPrimitive{}}, // no active exchange
	}

	tool := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, tool, "tool lookup must return the tool primitive")

	prompt := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	assert.Nil(t, prompt, "prompt lookup must not return the tool primitive")
}

func TestFindActivePrimitive_BothActive_TypeSelects(t *testing.T) {
	mw := &oas.Middleware{
		McpTools:   oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
		McpPrompts: oas.MCPPrimitives{"search": activePrimitive("https://prompt-api")},
	}

	tool := findActivePrimitive(mw, "search", mcp.PrimitiveTypeTool)
	require.NotNil(t, tool)
	assert.Equal(t, "https://tool-api", tool.Exchange.Audience)

	prompt := findActivePrimitive(mw, "search", mcp.PrimitiveTypePrompt)
	require.NotNil(t, prompt)
	assert.Equal(t, "https://prompt-api", prompt.Exchange.Audience)
}

func TestFindActivePrimitive_UnknownType_FallbackSearchesAll(t *testing.T) {
	mw := &oas.Middleware{
		McpTools: oas.MCPPrimitives{"search": activePrimitive("https://tool-api")},
	}
	got := findActivePrimitive(mw, "search", "")
	require.NotNil(t, got, "unknown type falls back to searching all maps")
}

func TestSubjectIDFromState_UsesSubClaimWhenPresent(t *testing.T) {
	st := &oauth2common.State{
		Claims:   jwt.MapClaims{oas.OAuth2ClaimSub: "user-123"},
		RawToken: "raw-token-value",
	}
	assert.Equal(t, "user-123", subjectIDFromState(st))
}

func TestSubjectIDFromState_FallsBackToFullTokenHashWhenSubMissing(t *testing.T) {
	st := &oauth2common.State{
		Claims:   jwt.MapClaims{},
		RawToken: "raw-token-value",
	}

	got := subjectIDFromState(st)

	want := fmt.Sprintf("%x", sha256.Sum256([]byte(st.RawToken)))
	assert.Equal(t, want, got, "fallback must be the full SHA-256 hex of the raw token")
	assert.Len(t, got, 64, "a truncated hash weakens collision resistance")
}

func TestSubjectIDFromState_DifferentTokensProduceDifferentIDs(t *testing.T) {
	a := subjectIDFromState(&oauth2common.State{Claims: jwt.MapClaims{}, RawToken: "token-a"})
	b := subjectIDFromState(&oauth2common.State{Claims: jwt.MapClaims{}, RawToken: "token-b"})
	assert.NotEqual(t, a, b)
}

// strictResourceIdP behaves like an IdP that enforces RFC 8707: any resource
// that is not an absolute URI without a fragment is rejected with
// invalid_target. It records every form it receives.
func strictResourceIdP(t *testing.T) (*httptest.Server, func() []url.Values) {
	t.Helper()
	var (
		mu    sync.Mutex
		forms []url.Values
	)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.PostForm)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		for _, resource := range r.PostForm[oas.OAuth2FormResource] {
			if !oas.IsResourceIndicator(resource) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_target",
					"error_description": "Must be an absolute URI without a fragment: " + resource,
				})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "exchanged", "expires_in": 60})
	}))
	t.Cleanup(idp.Close)
	return idp, func() []url.Values {
		mu.Lock()
		defer mu.Unlock()
		return forms
	}
}

func TestRunExchange_StrictResourceIdP(t *testing.T) {
	tests := []struct {
		name         string
		audience     string
		wantResource []string
	}{
		{name: "client id audience succeeds without resource", audience: "abc123"},
		{name: "URL audience still sends both", audience: "https://orders.example.com", wantResource: []string{"https://orders.example.com"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp, forms := strictResourceIdP(t)
			st := &oauth2common.State{
				Claims:   jwt.MapClaims{oas.OAuth2ClaimIss: "https://idp.example.com", oas.OAuth2ClaimSub: "user"},
				RawToken: "inbound",
				OASConfig: &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
					Providers: []oas.OAuth2TokenExchangeProvider{{
						Name:          "example",
						Issuers:       []string{"https://idp.example.com"},
						TokenEndpoint: idp.URL,
						ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "gateway", ClientSecret: "secret"},
						DefaultTarget: &oas.OAuth2DefaultTarget{Audience: tc.audience},
					}},
				}},
			}
			r := httptest.NewRequest(http.MethodGet, "/orders", nil)

			out, err := mwWithoutTykOps().runExchange(r, st)
			require.NoError(t, err)
			assert.Equal(t, "exchanged", out.ExchangedToken)
			assert.Equal(t, "Bearer exchanged", r.Header.Get("Authorization"))

			got := forms()
			require.Len(t, got, 1)
			assert.Equal(t, tc.audience, got[0].Get(oas.OAuth2FormAudience))
			assert.Equal(t, tc.wantResource, got[0][oas.OAuth2FormResource])
		})
	}
}

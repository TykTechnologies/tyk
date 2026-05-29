//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// runExchange performs the RFC 8693 exchange for the matched request.
func (m *Middleware) runExchange(r *http.Request, st *oauth2common.State) (oauth2common.Outcome, error) {
	out := oauth2common.Outcome{}
	cfg := st.OASConfig
	if cfg.TokenExchange == nil || len(cfg.TokenExchange.Providers) == 0 {
		return out, nil
	}

	// Gate provider matching per RFC 8693 §4.8 — no 403 if no exchange would fire.
	if !m.exchangeWouldFire(st, cfg) {
		return out, nil
	}

	iss, _ := st.Claims[oas.OAuth2ClaimIss].(string)
	provider := oauth2common.SelectExchangeProvider(cfg.TokenExchange.Providers, iss)
	if provider == nil {
		return out, &oauth2common.NoMatchingProviderError{Iss: iss}
	}
	out.ProviderName = provider.Name

	target := m.resolveExchangeTarget(st, provider)
	if target == nil {
		return out, &oauth2common.MisconfigError{
			Reason: fmt.Sprintf("token exchange is configured for this request but audience could not be resolved (per-op exchange.audience and provider %q defaultTarget.audience are both empty)", provider.Name),
		}
	}
	out.Audience = target.Audience
	out.Scopes = target.Scopes

	exchanged, err := m.fetchExchangedToken(r, st, provider, target)
	if err != nil {
		return out, err
	}
	out.ExchangedToken = exchanged
	r.Header.Set(header.Authorization, oas.OAuth2AuthSchemeBearer+" "+exchanged)
	return out, nil
}

// subjectIDFromState derives a subject identifier from the inbound token state.
// Uses the "sub" claim when present; falls back to a 12-character hash of the raw token.
func subjectIDFromState(st *oauth2common.State) string {
	if sub := oauth2common.StringClaim(st.Claims, "sub"); sub != "" {
		return sub
	}
	h := sha256.Sum256([]byte(st.RawToken))
	return fmt.Sprintf("%x", h)[:12]
}

// inboundRemaining returns how long the inbound token has left, or 0 if unknown.
func inboundRemaining(st *oauth2common.State) time.Duration {
	expVal, ok := st.Claims["exp"]
	if !ok {
		return 0
	}
	var expUnix int64
	switch v := expVal.(type) {
	case float64:
		expUnix = int64(v)
	case int64:
		expUnix = v
	default:
		return 0
	}
	remaining := time.Until(time.Unix(expUnix, 0))
	if remaining <= 0 {
		return 0
	}
	return remaining
}

// fetchExchangedToken returns an exchanged token, using the cache when configured and enabled.
func (m *Middleware) fetchExchangedToken(r *http.Request, st *oauth2common.State, provider *oas.OAuth2TokenExchangeProvider, target *oauth2common.Target) (string, error) {
	if m.Cache == nil || provider.Cache == nil || !provider.Cache.Enabled {
		token, _, err := m.exchangeAtIdP(r.Context(), provider, st.RawToken, target)
		return token, err
	}

	subjectID := subjectIDFromState(st)
	cacheKey := oauth2common.CacheKeyInput{
		SubjectID:    subjectID,
		APIID:        st.APIID,
		Audience:     target.Audience,
		Scopes:       target.Scopes,
		ProviderName: provider.Name,
	}.Build()

	log := m.Logger()

	token, ttlRemaining, hit, err := m.Cache.GetOrFetch(cacheKey, func() (string, time.Duration, error) {
		log.WithFields(logrus.Fields{
			"api_id":   st.APIID,
			"provider": provider.Name,
			"audience": target.Audience,
		}).Info("token exchange cache miss")

		tok, expiresIn, fetchErr := m.exchangeAtIdP(r.Context(), provider, st.RawToken, target)
		if fetchErr != nil {
			return "", 0, fetchErr
		}

		safetyMargin := time.Duration(provider.Cache.SafetyMargin)
		if safetyMargin == 0 {
			safetyMargin = oauth2common.DefaultSafetyMargin
		}

		var ttl time.Duration
		switch provider.Cache.Mode {
		case oas.OAuth2CacheModeStatic:
			ttl = oauth2common.StaticTTL(time.Duration(provider.Cache.Timeout), expiresIn, safetyMargin)
		default:
			ttl = oauth2common.DerivedTTL(expiresIn, inboundRemaining(st), time.Duration(provider.Cache.MaxTimeout), safetyMargin)
		}
		return tok, ttl, nil
	})
	if err != nil {
		return "", err
	}

	if hit && ttlRemaining > 0 {
		log.WithFields(logrus.Fields{
			"api_id":        st.APIID,
			"provider":      provider.Name,
			"ttl_remaining": int64(ttlRemaining.Seconds()),
		}).Debug("token exchange cache hit")
	}

	return token, nil
}

// findActivePrimitive returns the first primitive in tools/resources/prompts with the given name and active exchange.
func findActivePrimitive(mw *oas.Middleware, name string) *oas.MCPPrimitive {
	for _, prims := range []oas.MCPPrimitives{mw.McpTools, mw.McpResources, mw.McpPrompts} {
		if prim, ok := prims[name]; ok && prim != nil && prim.Exchange.IsActive() {
			return prim
		}
	}
	return nil
}

// exchangeWouldFire reports whether an exchange target exists for this request (RFC 8693 §4.8).
func (m *Middleware) exchangeWouldFire(st *oauth2common.State, cfg *oas.OAuth2) bool {
	if mw := m.Spec.OAS.GetTykMiddleware(); mw != nil {
		if st.MatchedPrimitiveName != "" && findActivePrimitive(mw, st.MatchedPrimitiveName) != nil {
			return true
		}
		if st.MatchedOperationID != "" {
			if tykOp, ok := mw.Operations[st.MatchedOperationID]; ok && tykOp != nil && tykOp.Exchange.IsActive() {
				return true
			}
		}
	}
	for _, p := range cfg.TokenExchange.Providers {
		if p.DefaultTarget != nil && p.DefaultTarget.Audience != "" {
			return true
		}
	}
	return false
}

// resolveExchangeTarget resolves the audience+scopes pair for the matched provider.
// Resolution priority: per-primitive exchange > per-operation exchange > provider defaultTarget.
// A block with exchange.enabled=false is skipped; resolution falls through to the provider default.
func (m *Middleware) resolveExchangeTarget(st *oauth2common.State, provider *oas.OAuth2TokenExchangeProvider) *oauth2common.Target {
	if mw := m.Spec.OAS.GetTykMiddleware(); mw != nil {
		if st.MatchedPrimitiveName != "" {
			if prim := findActivePrimitive(mw, st.MatchedPrimitiveName); prim != nil {
				return oauth2common.MergeTargetForProvider(prim.Exchange, provider, st.InferredScopes)
			}
		}
		if st.MatchedOperationID != "" {
			if tykOp, ok := mw.Operations[st.MatchedOperationID]; ok && tykOp != nil && tykOp.Exchange.IsActive() {
				return oauth2common.MergeTargetForProvider(tykOp.Exchange, provider, st.InferredScopes)
			}
		}
	}
	if provider.DefaultTarget != nil && provider.DefaultTarget.Audience != "" {
		return &oauth2common.Target{
			Audience: provider.DefaultTarget.Audience,
			Scopes:   append([]string(nil), provider.DefaultTarget.Scopes...),
		}
	}
	return nil
}

// exchangeAtIdP posts the RFC 8693 exchange form to the provider's token endpoint.
// Returns the exchanged access token and the expires_in value from the response (0 if not provided).
func (m *Middleware) exchangeAtIdP(ctx context.Context, provider *oas.OAuth2TokenExchangeProvider, subjectToken string, target *oauth2common.Target) (string, time.Duration, error) {
	if provider.TokenEndpoint == "" {
		return "", 0, errors.New("provider tokenEndpoint is empty")
	}

	method := ""
	if provider.ClientAuth != nil {
		method = provider.ClientAuth.Method
	}

	form := url.Values{}
	form.Set(oas.OAuth2FormGrantType, oas.OAuth2GrantTypeTokenExchange)
	form.Set(oas.OAuth2FormSubjectToken, subjectToken)
	form.Set(oas.OAuth2FormSubjectTokenType, oas.OAuth2TokenTypeAccessToken)
	if target.Audience != "" {
		form.Set(oas.OAuth2FormAudience, target.Audience)
		form.Set(oas.OAuth2FormResource, target.Audience)
	}
	if len(target.Scopes) > 0 {
		form.Set(oas.OAuth2FormScope, strings.Join(target.Scopes, " "))
	}
	for k, v := range provider.CustomParams {
		form.Set(k, v)
	}
	if method == oas.OAuth2ClientAuthPost && provider.ClientAuth != nil {
		if provider.ClientAuth.ClientID != "" {
			form.Set(oas.OAuth2FormClientID, provider.ClientAuth.ClientID)
		}
		if provider.ClientAuth.ClientSecret != "" {
			form.Set(oas.OAuth2FormClientSecret, provider.ClientAuth.ClientSecret)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("building exchange request: %w", err)
	}
	req.Header.Set(header.ContentType, header.ApplicationFormURLEncoded)

	switch method {
	case oas.OAuth2ClientAuthPost:
		// credentials already injected into form above
	case "", oas.OAuth2ClientAuthBasic:
		if provider.ClientAuth != nil && provider.ClientAuth.ClientID != "" {
			req.SetBasicAuth(provider.ClientAuth.ClientID, provider.ClientAuth.ClientSecret)
		}
	default:
		return "", 0, fmt.Errorf("unsupported clientAuth.method %q", method)
	}

	client := oauth2common.NewIdPHTTPClient(EffectiveIdPTimeout(time.Duration(provider.Timeout)))
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("exchange call failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauth2common.MaxIdPResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		idpErr, idpDesc := oauth2common.DecodeIdPError(body)
		return "", 0, &oauth2common.ExchangeFailedError{
			Status:      resp.StatusCode,
			IdpError:    idpErr,
			Description: idpDesc,
		}
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("decoding exchange response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", 0, errors.New("exchange response missing access_token")
	}
	var expiresIn time.Duration
	if parsed.ExpiresIn > 0 {
		expiresIn = time.Duration(parsed.ExpiresIn) * time.Second
	}
	return parsed.AccessToken, expiresIn, nil
}

// writeJSONError writes a JSON error response with the given status and Bearer challenge.
func (m *Middleware) writeJSONError(w http.ResponseWriter, r *http.Request, status int, wwwParams [][2]string, body map[string]string) {
	enc, _ := json.Marshal(body)
	m.setExchangeWWWAuthenticate(w, r, wwwParams)
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(status)
	_, _ = w.Write(enc)
}

// writeExchangeFailedResponse renders a 502 for an IdP-side exchange failure.
func (m *Middleware) writeExchangeFailedResponse(w http.ResponseWriter, r *http.Request, err error) {
	body := map[string]string{oas.OAuth2FieldError: oas.OAuth2ErrExchangeFailed}
	if oe, ok := err.(*oauth2common.ExchangeFailedError); ok {
		if oe.IdpError != "" {
			body[oas.OAuth2FieldIdpError] = oe.IdpError
		}
		if oe.Description != "" {
			body[oas.OAuth2FieldIdpErrorDescription] = oe.Description
		}
	} else {
		body[oas.OAuth2FieldIdpErrorDescription] = err.Error()
	}
	m.writeJSONError(w, r, http.StatusBadGateway, [][2]string{
		{oas.OAuth2FieldError, oas.OAuth2ErrExchangeFailed},
		{oas.OAuth2FieldErrorDescription, body[oas.OAuth2FieldIdpErrorDescription]},
	}, body)
}

// writeNoMatchingProviderResponse renders a 403 when no provider matches the inbound iss.
func (m *Middleware) writeNoMatchingProviderResponse(w http.ResponseWriter, r *http.Request, oe *oauth2common.NoMatchingProviderError) {
	m.writeJSONError(w, r, http.StatusForbidden, [][2]string{
		{oas.OAuth2FieldError, oas.OAuth2ErrNoMatchingProvider},
		{oas.OAuth2FieldErrorDescription, oe.Error()},
	}, map[string]string{
		oas.OAuth2FieldError:            oas.OAuth2ErrNoMatchingProvider,
		oas.OAuth2FieldErrorDescription: oe.Error(),
		oas.OAuth2ClaimIss:              oe.Iss,
	})
}

// writeMisconfigResponse renders a 500 for an incomplete exchange configuration.
func (m *Middleware) writeMisconfigResponse(w http.ResponseWriter, r *http.Request, me *oauth2common.MisconfigError) {
	m.writeJSONError(w, r, http.StatusInternalServerError, [][2]string{
		{oas.OAuth2FieldError, oas.OAuth2ErrMisconfigured},
		{oas.OAuth2FieldErrorDescription, me.Error()},
	}, map[string]string{
		oas.OAuth2FieldError:            oas.OAuth2ErrMisconfigured,
		oas.OAuth2FieldErrorDescription: me.Error(),
	})
}

// setExchangeWWWAuthenticate writes an RFC 6750 Bearer challenge with the given params.
func (m *Middleware) setExchangeWWWAuthenticate(w http.ResponseWriter, r *http.Request, params [][2]string) {
	authParams := make([]string, 0, len(params)+1)
	for _, kv := range params {
		authParams = append(authParams, fmt.Sprintf("%s=%q", kv[0], kv[1]))
	}
	if u := m.prmAbsoluteURL(r); u != "" {
		authParams = append(authParams, fmt.Sprintf("%s=%q", oas.OAuth2FieldResourceMetadata, u))
	}
	w.Header().Set(header.WWWAuthenticate, oas.OAuth2AuthSchemeBearer+" "+strings.Join(authParams, ", "))
}

// prmAbsoluteURL returns the PRM well-known URL for this API, or "" if PRM is not configured.
func (m *Middleware) prmAbsoluteURL(r *http.Request) string {
	cfg := m.lookupOAuth2Config()
	if cfg == nil || cfg.ProtectedResourceMetadata == nil || !cfg.ProtectedResourceMetadata.Enabled {
		return ""
	}
	wellKnown := cfg.ProtectedResourceMetadata.GetWellKnownPath()
	if wellKnown == "" {
		return ""
	}
	scheme := httputil.RequestScheme(r)
	listenPath := m.Spec.APIDefinition.Proxy.ListenPath
	full := strings.TrimSuffix(listenPath, "/") + wellKnown
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, full)
}

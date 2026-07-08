//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// runExchange performs the RFC 8693 exchange for the matched request.
func (m *Middleware) runExchange(r *http.Request, st *oauth2common.State) (oauth2common.Outcome, error) {
	out := oauth2common.Outcome{}
	cfg := st.OASConfig
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

	start := time.Now()
	exchanged, cacheHit, err := m.fetchExchangedToken(r, st, provider, target)
	out.CacheHit = cacheHit
	out.Duration = time.Since(start)
	if err != nil {
		var fe *oauth2common.ExchangeFailedError
		if errors.As(err, &fe) {
			out.IdpErrorCode = fe.IdpError
			out.IdpErrorDesc = fe.Description
		}
		return out, err
	}
	out.ExchangedToken = exchanged
	r.Header.Set(header.Authorization, oas.OAuth2AuthSchemeBearer+" "+exchanged)
	return out, nil
}

// subjectIDFromState derives a subject identifier from the inbound token state.
// Uses the "sub" claim when present; falls back to a SHA-256 hash of the raw token.
func subjectIDFromState(st *oauth2common.State) string {
	if sub := oauth2common.StringClaim(st.Claims, oas.OAuth2ClaimSub); sub != "" {
		return sub
	}
	h := sha256.Sum256([]byte(st.RawToken))
	return fmt.Sprintf("%x", h)
}

// inboundRemaining returns how long the inbound token has left, or 0 if unknown.
func inboundRemaining(st *oauth2common.State) time.Duration {
	expVal, ok := st.Claims[oas.OAuth2ClaimExp]
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

// fetchExchangedToken returns an exchanged token, using the cache when configured
// and enabled. It also reports whether the token was served from cache. The
// caller times the call for the duration metric.
func (m *Middleware) fetchExchangedToken(r *http.Request, st *oauth2common.State, provider *oas.OAuth2TokenExchangeProvider, target *oauth2common.Target) (string, bool, error) {
	// Standard gateway variable replacement, e.g. $tyk_context.jwt_claims_tid.
	endpoint := provider.TokenEndpoint
	if st.ReplaceVariables != nil {
		endpoint = st.ReplaceVariables(endpoint)
	}
	tenantEndpoint := ""
	if endpoint != provider.TokenEndpoint {
		// Per-tenant endpoint: exchange against a copy so the shared provider
		// config is never mutated, and key the cache by the resolved endpoint
		// so a token cached for one tenant is never served for another.
		tenantEndpoint = endpoint
		resolved := *provider
		resolved.TokenEndpoint = endpoint
		provider = &resolved
	}

	if m.Cache == nil || provider.Cache == nil || !provider.Cache.Enabled {
		token, _, err := m.exchangeAtIdP(r.Context(), provider, st.RawToken, target)
		return token, false, err
	}

	subjectID := subjectIDFromState(st)
	cacheKey := oauth2common.CacheKeyInput{
		Issuer:         oauth2common.StringClaim(st.Claims, oas.OAuth2ClaimIss),
		SubjectID:      subjectID,
		APIID:          st.APIID,
		Audience:       target.Audience,
		Scopes:         target.Scopes,
		ProviderName:   provider.Name,
		TenantEndpoint: tenantEndpoint,
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
		return tok, cacheTTL(provider.Cache, expiresIn, inboundRemaining(st)), nil
	})
	if err != nil {
		return "", false, err
	}

	if hit && ttlRemaining > 0 {
		log.WithFields(logrus.Fields{
			"api_id":        st.APIID,
			"provider":      provider.Name,
			"ttl_remaining": int64(ttlRemaining.Seconds()),
		}).Debug("token exchange cache hit")
	}

	return token, hit, nil
}

// cacheTTL derives the cache entry lifetime for the provider's cache mode,
// defaulting the safety margin when none is configured.
func cacheTTL(cache *oas.OAuth2ExchangeCache, expiresIn, inboundRemaining time.Duration) time.Duration {
	safetyMargin := time.Duration(cache.SafetyMargin)
	if safetyMargin == 0 {
		safetyMargin = oauth2common.DefaultSafetyMargin
	}
	if cache.Mode == oas.OAuth2CacheModeStatic {
		return oauth2common.StaticTTL(time.Duration(cache.Timeout), expiresIn, safetyMargin)
	}
	return oauth2common.DerivedTTL(expiresIn, inboundRemaining, time.Duration(cache.MaxTimeout), safetyMargin)
}

// findActivePrimitive returns the primitive with the given name and active exchange
// from the map that matches primitiveType. Tool, resource, and prompt names occupy
// independent namespaces; lookup without a type falls back to searching all maps.
func findActivePrimitive(mw *oas.Middleware, name, primitiveType string) *oas.MCPPrimitive {
	var prims oas.MCPPrimitives
	switch primitiveType {
	case mcp.PrimitiveTypeTool:
		prims = mw.McpTools
	case mcp.PrimitiveTypeResource:
		prims = mw.McpResources
	case mcp.PrimitiveTypePrompt:
		prims = mw.McpPrompts
	default:
		for _, ps := range []oas.MCPPrimitives{mw.McpTools, mw.McpResources, mw.McpPrompts} {
			if prim, ok := ps[name]; ok && prim != nil && prim.Exchange.IsActive() {
				return prim
			}
		}
		return nil
	}
	if prim, ok := prims[name]; ok && prim != nil && prim.Exchange.IsActive() {
		return prim
	}
	return nil
}

// exchangeWouldFire reports whether an exchange target exists for this request
// (RFC 8693 §4.8): providers are configured and a per-primitive, per-operation,
// or provider-default target resolves.
func (m *Middleware) exchangeWouldFire(st *oauth2common.State, cfg *oas.OAuth2) bool {
	if cfg.TokenExchange == nil || len(cfg.TokenExchange.Providers) == 0 {
		return false
	}
	if mw := m.Spec.OAS.GetTykMiddleware(); mw != nil {
		if st.MatchedPrimitiveName != "" && findActivePrimitive(mw, st.MatchedPrimitiveName, st.MatchedPrimitiveType) != nil {
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
			if prim := findActivePrimitive(mw, st.MatchedPrimitiveName, st.MatchedPrimitiveType); prim != nil {
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

	form := buildExchangeForm(provider, subjectToken, target, method)

	if method == oas.OAuth2ClientAuthPrivateKeyJWT {
		if err := m.addClientAssertion(form, provider); err != nil {
			return "", 0, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("building exchange request: %w", err)
	}
	req.Header.Set(header.ContentType, header.ApplicationFormURLEncoded)
	if err := applyClientAuth(req, provider, method); err != nil {
		return "", 0, err
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
		// interaction_required means the user must sign in again — a message
		// for the caller, relayed as a 401 step-up challenge instead of being
		// collapsed to idp_error. Scoped to the jwt-bearer grant; the RFC 8693
		// error path is shipped behaviour and stays unchanged.
		if provider.IsJWTBearer() && idpErr == oas.OAuth2ErrInteractionRequired {
			claims, authURI := oauth2common.DecodeClaimsChallenge(body)
			return "", 0, &oauth2common.StepUpRequiredError{
				Claims:           claims,
				AuthorizationURI: authURI,
			}
		}
		return "", 0, &oauth2common.ExchangeFailedError{
			Status:      resp.StatusCode,
			IdpError:    idpErr,
			Description: idpDesc,
		}
	}

	return parseExchangeResponse(body)
}

// buildExchangeForm builds the exchange request form for the provider's grant.
// RFC 8693 (the default) sends the inbound token as subject_token with the
// target as separate audience/resource/scope parameters; jwt-bearer (RFC 7523)
// sends it as `assertion` with the target rendered into `scope`. When the
// client-auth method is client_secret_post, credentials are injected into the
// form here (basic-auth credentials are set on the request header instead).
func buildExchangeForm(provider *oas.OAuth2TokenExchangeProvider, subjectToken string, target *oauth2common.Target, method string) url.Values {
	if provider.IsJWTBearer() {
		return buildJWTBearerForm(provider, subjectToken, target, method)
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
	addCustomParams(form, provider)
	addPostClientCredentials(form, provider, method)
	return form
}

// buildJWTBearerForm builds the RFC 7523 jwt-bearer request: the inbound token
// as `assertion` and the target rendered into `scope` by the prefix rule (see
// oauth2common.RenderJWTBearerScope). The grant emits no audience or resource
// wire parameter — the audience is consumed by the scope rendering — and no
// IdP-specific flag of its own; those travel via customParams.
func buildJWTBearerForm(provider *oas.OAuth2TokenExchangeProvider, subjectToken string, target *oauth2common.Target, method string) url.Values {
	form := url.Values{}
	form.Set(oas.OAuth2FormGrantType, oas.OAuth2GrantTypeJWTBearer)
	form.Set(oas.OAuth2FormAssertion, subjectToken)
	if scope := oauth2common.RenderJWTBearerScope(target.Audience, target.Scopes); scope != "" {
		form.Set(oas.OAuth2FormScope, scope)
	}
	addCustomParams(form, provider)
	addPostClientCredentials(form, provider, method)
	return form
}

// addCustomParams appends the provider's operator-supplied form parameters.
func addCustomParams(form url.Values, provider *oas.OAuth2TokenExchangeProvider) {
	for k, v := range provider.CustomParams {
		form.Set(k, v)
	}
}

// addPostClientCredentials injects client_id/client_secret into the form for
// the client_secret_post method; a no-op for basic (set on the request header).
func addPostClientCredentials(form url.Values, provider *oas.OAuth2TokenExchangeProvider, method string) {
	if method != oas.OAuth2ClientAuthPost || provider.ClientAuth == nil {
		return
	}
	if provider.ClientAuth.ClientID != "" {
		form.Set(oas.OAuth2FormClientID, provider.ClientAuth.ClientID)
	}
	if provider.ClientAuth.ClientSecret != "" {
		form.Set(oas.OAuth2FormClientSecret, provider.ClientAuth.ClientSecret)
	}
}

// applyClientAuth sets the request-level client authentication for the exchange
// call. client_secret_post credentials are already in the form, so this is a
// no-op for that method; basic (the default) sets the Authorization header.
func applyClientAuth(req *http.Request, provider *oas.OAuth2TokenExchangeProvider, method string) error {
	switch method {
	case oas.OAuth2ClientAuthPost, oas.OAuth2ClientAuthPrivateKeyJWT:
		// credentials already injected into the form (client_secret_post or the
		// signed private_key_jwt client_assertion).
	case "", oas.OAuth2ClientAuthBasic:
		if provider.ClientAuth != nil && provider.ClientAuth.ClientID != "" {
			req.SetBasicAuth(provider.ClientAuth.ClientID, provider.ClientAuth.ClientSecret)
		}
	default:
		return fmt.Errorf("unsupported clientAuth.method %q", method)
	}
	return nil
}

// parseExchangeResponse decodes a successful IdP exchange response into the
// exchanged access token and its lifetime (0 when expires_in is absent).
func parseExchangeResponse(body []byte) (string, time.Duration, error) {
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

// writeStepUpRequiredResponse renders a 401 with a Bearer insufficient_claims
// challenge relaying the IdP's claims challenge. The claims are base64-encoded
// with padding (the de-facto claims-challenge convention) on the
// WWW-Authenticate header; absent fields are omitted rather than sent empty.
// The upstream is never called and nothing is cached.
func (m *Middleware) writeStepUpRequiredResponse(w http.ResponseWriter, r *http.Request, e *oauth2common.StepUpRequiredError) {
	params := [][2]string{{oas.OAuth2FieldError, oas.OAuth2ErrInsufficientClaims}}
	body := map[string]string{oas.OAuth2FieldError: oas.OAuth2ErrInsufficientClaims}
	if e.Claims != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(e.Claims))
		params = append(params, [2]string{oas.OAuth2FieldClaims, encoded})
		body[oas.OAuth2FieldClaims] = encoded
	}
	if e.AuthorizationURI != "" {
		params = append(params, [2]string{oas.OAuth2FieldAuthorizationURI, e.AuthorizationURI})
		body[oas.OAuth2FieldAuthorizationURI] = e.AuthorizationURI
	}
	m.writeJSONError(w, r, http.StatusUnauthorized, params, body)
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

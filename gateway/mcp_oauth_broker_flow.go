package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/header"
)

const (
	mcpOAuthBrokerCodeTTL           = 5 * time.Minute
	mcpOAuthBrokerAccessTokenTTL    = time.Hour
	mcpOAuthBrokerRefreshTokenTTL   = 24 * time.Hour
	mcpOAuthBrokerReplayMarkerTTL   = 24 * time.Hour
	mcpOAuthBrokerTokenType         = "Bearer"
	mcpOAuthBrokerMaxErrorTextBytes = 256
)

type mcpOAuthDownstreamCode struct {
	OrgID                string `json:"org_id"`
	APIID                string `json:"api_id"`
	PublicIssuer         string `json:"public_issuer"`
	PublicResource       string `json:"public_resource"`
	DownstreamClientID   string `json:"downstream_client_id"`
	RedirectURI          string `json:"redirect_uri"`
	DownstreamChallenge  string `json:"downstream_challenge"`
	Scope                string `json:"scope"`
	UpstreamIssuer       string `json:"upstream_issuer"`
	UpstreamResource     string `json:"upstream_resource"`
	UpstreamToken        string `json:"upstream_token_endpoint"`
	UpstreamClientID     string `json:"upstream_client_id"`
	UpstreamAccessToken  string `json:"upstream_access_token"`
	UpstreamRefreshToken string `json:"upstream_refresh_token,omitempty"`
	UpstreamExpiresAt    int64  `json:"upstream_expires_at"`
}

type mcpOAuthTokenGrant struct {
	OrgID                string `json:"org_id"`
	APIID                string `json:"api_id"`
	PublicIssuer         string `json:"public_issuer"`
	PublicResource       string `json:"public_resource"`
	DownstreamClientID   string `json:"downstream_client_id"`
	Scope                string `json:"scope"`
	FamilyID             string `json:"family_id"`
	UpstreamIssuer       string `json:"upstream_issuer"`
	UpstreamResource     string `json:"upstream_resource"`
	UpstreamToken        string `json:"upstream_token_endpoint"`
	UpstreamClientID     string `json:"upstream_client_id"`
	UpstreamAccessToken  string `json:"upstream_access_token"`
	UpstreamRefreshToken string `json:"upstream_refresh_token,omitempty"`
	UpstreamExpiresAt    int64  `json:"upstream_expires_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

type mcpOAuthUpstreamTokenResponse struct {
	AccessToken  string
	RefreshToken string
	Scope        string
	ExpiresIn    time.Duration
}

func (b *mcpOAuthBroker) callbackHandler(w http.ResponseWriter, r *http.Request) {
	mcpOAuthSetNoStore(w)
	if !b.validPublicRequest(r) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	query := r.URL.Query()
	stateValue, ok := singleOAuthValue(query, "state", true)
	if !ok {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	stateKey := mcpOAuthBrokerKey("state", b.spec.OrgID, b.spec.APIID, stateValue)
	var state mcpOAuthAuthorizationState
	found, err := b.consumeRecord(r.Context(), stateKey, &state)
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !found || !b.validAuthorizationState(state) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}

	issuer, issuerPresent, issuerValid := optionalSingleOAuthValue(query, "iss")
	if !issuerValid || (issuerPresent && issuer != state.UpstreamIssuer) || (state.UpstreamSupportsISS && !issuerPresent) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	code, hasCode, codeValid := optionalSingleOAuthValue(query, "code")
	errorCode, hasError, errorValid := optionalSingleOAuthValue(query, "error")
	if !codeValid || !errorValid || hasCode == hasError {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if hasError {
		if !validOAuthErrorCode(errorCode) {
			mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
			return
		}
		target, err := brokerRedirect(state.RedirectURI, url.Values{
			"error": {errorCode}, "state": {state.OriginalState}, "iss": {state.PublicIssuer},
		})
		if err != nil {
			mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	upstream, err := b.exchangeUpstreamCode(r.Context(), state, code)
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	downstreamCode, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusInternalServerError, "server_error")
		return
	}
	record := mcpOAuthDownstreamCode{
		OrgID: state.OrgID, APIID: state.APIID, PublicIssuer: state.PublicIssuer, PublicResource: state.PublicResource,
		DownstreamClientID: state.DownstreamClientID, RedirectURI: state.RedirectURI,
		DownstreamChallenge: state.DownstreamChallenge, Scope: upstream.Scope,
		UpstreamIssuer: state.UpstreamIssuer, UpstreamResource: state.UpstreamResource,
		UpstreamToken: state.UpstreamToken, UpstreamClientID: state.UpstreamClientID,
		UpstreamAccessToken: upstream.AccessToken, UpstreamRefreshToken: upstream.RefreshToken,
		UpstreamExpiresAt: time.Now().Add(upstream.ExpiresIn).Unix(),
	}
	if err := b.putRecord(r.Context(), b.codeKey(downstreamCode), record, mcpOAuthBrokerCodeTTL); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	target, err := brokerRedirect(state.RedirectURI, url.Values{
		"code": {downstreamCode}, "state": {state.OriginalState}, "iss": {state.PublicIssuer},
	})
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (b *mcpOAuthBroker) tokenHandler(w http.ResponseWriter, r *http.Request) {
	mcpOAuthSetNoStore(w)
	if !b.validPublicRequest(r) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	form, err := readOAuthForm(w, r)
	if err != nil || r.Header.Get(header.Authorization) != "" {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	grantType, ok := singleOAuthValue(form, "grant_type", true)
	if !ok {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	switch grantType {
	case "authorization_code":
		b.authorizationCodeToken(w, r, form)
	case "refresh_token":
		b.refreshToken(w, r, form)
	default:
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (b *mcpOAuthBroker) authorizationCodeToken(w http.ResponseWriter, r *http.Request, form url.Values) {
	if !exactOAuthFormFields(form, []string{"grant_type", "code", "client_id", "redirect_uri", "code_verifier", "resource"}) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	codeValue, codeOK := singleOAuthValue(form, "code", true)
	clientID, clientOK := singleOAuthValue(form, "client_id", true)
	redirectURI, redirectOK := singleOAuthValue(form, "redirect_uri", true)
	verifier, verifierOK := singleOAuthValue(form, "code_verifier", true)
	resource, resourceOK := singleOAuthValue(form, "resource", true)
	if !codeOK || !clientOK || !redirectOK || !verifierOK || !resourceOK || !validMCPOAuthPKCE(verifier) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var code mcpOAuthDownstreamCode
	found, err := b.consumeRecord(r.Context(), b.codeKey(codeValue), &code)
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !found || !b.validDownstreamCode(code, clientID, redirectURI, resource) ||
		mcpOAuthPKCEChallenge(verifier) != code.DownstreamChallenge {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	familyID, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusInternalServerError, "server_error")
		return
	}
	grant := mcpOAuthTokenGrant{
		OrgID: code.OrgID, APIID: code.APIID, PublicIssuer: code.PublicIssuer, PublicResource: code.PublicResource,
		DownstreamClientID: code.DownstreamClientID, Scope: code.Scope, FamilyID: familyID,
		UpstreamIssuer: code.UpstreamIssuer, UpstreamResource: code.UpstreamResource,
		UpstreamToken: code.UpstreamToken, UpstreamClientID: code.UpstreamClientID,
		UpstreamAccessToken: code.UpstreamAccessToken, UpstreamRefreshToken: code.UpstreamRefreshToken,
		UpstreamExpiresAt: code.UpstreamExpiresAt,
	}
	b.issueDownstreamTokens(w, r, grant)
}

func (b *mcpOAuthBroker) refreshToken(w http.ResponseWriter, r *http.Request, form url.Values) {
	if !exactOAuthFormFields(form, []string{"grant_type", "refresh_token", "client_id", "resource"}) {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	refreshValue, refreshOK := singleOAuthValue(form, "refresh_token", true)
	clientID, clientOK := singleOAuthValue(form, "client_id", true)
	resource, resourceOK := singleOAuthValue(form, "resource", true)
	if !refreshOK || !clientOK || !resourceOK {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_request")
		return
	}
	refreshKey := b.refreshKey(refreshValue)
	var grant mcpOAuthTokenGrant
	found, err := b.consumeRecord(r.Context(), refreshKey, &grant)
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !found {
		var issued mcpOAuthTokenGrant
		replay, err := b.getRecord(r.Context(), b.refreshFamilyKey(refreshValue), &issued)
		if err != nil {
			mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		if replay {
			if issued.FamilyID == "" {
				mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
				return
			}
			if err := b.putRecord(r.Context(), b.revokedFamilyKey(issued.FamilyID), map[string]bool{"revoked": true}, mcpOAuthBrokerReplayMarkerTTL); err != nil && !errors.Is(err, errMCPOAuthBrokerStoreCollision) {
				mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
				return
			}
		}
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !b.validGrant(grant, clientID, resource) || grant.UpstreamRefreshToken == "" {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if revoked, err := b.refreshFamilyRevoked(r.Context(), grant.FamilyID); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	} else if revoked {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	upstream, err := b.exchangeUpstreamRefresh(r.Context(), grant)
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	grant.UpstreamAccessToken = upstream.AccessToken
	if upstream.RefreshToken != "" {
		grant.UpstreamRefreshToken = upstream.RefreshToken
	}
	grant.Scope = upstream.Scope
	grant.UpstreamExpiresAt = time.Now().Add(upstream.ExpiresIn).Unix()
	b.issueDownstreamTokens(w, r, grant)
}

func (b *mcpOAuthBroker) issueDownstreamTokens(w http.ResponseWriter, r *http.Request, grant mcpOAuthTokenGrant) {
	if revoked, err := b.refreshFamilyRevoked(r.Context(), grant.FamilyID); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	} else if revoked {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	accessToken, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusInternalServerError, "server_error")
		return
	}
	refreshToken, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthErrorNoStore(w, http.StatusInternalServerError, "server_error")
		return
	}
	now := time.Now()
	accessTTL := mcpOAuthBrokerAccessTokenTTL
	if remaining := time.Until(time.Unix(grant.UpstreamExpiresAt, 0)); remaining < accessTTL {
		accessTTL = remaining
	}
	if accessTTL <= 0 {
		mcpOAuthErrorNoStore(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	grant.ExpiresAt = now.Add(accessTTL).Unix()
	if err := b.putRecord(r.Context(), b.accessKey(accessToken), grant, accessTTL); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err := b.putRecord(r.Context(), b.refreshFamilyKey(refreshToken), grant, mcpOAuthBrokerRefreshTokenTTL); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if err := b.putRecord(r.Context(), b.refreshKey(refreshToken), grant, mcpOAuthBrokerRefreshTokenTTL); err != nil {
		mcpOAuthErrorNoStore(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	mcpOAuthJSONNoStore(w, http.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": mcpOAuthBrokerTokenType,
		"expires_in": int64(accessTTL / time.Second), "refresh_token": refreshToken,
		"scope": grant.Scope,
	})
}

func (b *mcpOAuthBroker) refreshFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return false, errors.New("missing MCP OAuth refresh family")
	}
	var marker map[string]bool
	found, err := b.getRecord(ctx, b.revokedFamilyKey(familyID), &marker)
	if err != nil {
		return false, err
	}
	return found, nil
}

func (b *mcpOAuthBroker) exchangeUpstreamCode(ctx context.Context, state mcpOAuthAuthorizationState, code string) (mcpOAuthUpstreamTokenResponse, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {state.UpstreamClientID},
		"redirect_uri": {b.callbackURL()}, "code_verifier": {state.UpstreamVerifier}, "resource": {state.UpstreamResource},
	}
	return b.exchangeUpstreamToken(ctx, state.UpstreamIssuer, state.UpstreamToken, state.Scope, form)
}

func (b *mcpOAuthBroker) exchangeUpstreamRefresh(ctx context.Context, grant mcpOAuthTokenGrant) (mcpOAuthUpstreamTokenResponse, error) {
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {grant.UpstreamRefreshToken},
		"client_id": {grant.UpstreamClientID}, "resource": {grant.UpstreamResource},
	}
	return b.exchangeUpstreamToken(ctx, grant.UpstreamIssuer, grant.UpstreamToken, grant.Scope, form)
}

func (b *mcpOAuthBroker) exchangeUpstreamToken(ctx context.Context, issuer, endpoint, scope string, form url.Values) (mcpOAuthUpstreamTokenResponse, error) {
	if !trustedMCPOAuthEndpoint(issuer, endpoint, b.config.AllowInsecureLoopback) {
		return mcpOAuthUpstreamTokenResponse{}, errors.New("invalid upstream token endpoint")
	}
	response, err := b.doUpstream(ctx, http.MethodPost, endpoint, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return mcpOAuthUpstreamTokenResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, mcpOAuthBrokerBodyMax+1))
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get(header.ContentType))
	if err != nil || len(body) > mcpOAuthBrokerBodyMax || response.StatusCode/100 != 2 || mediaErr != nil || mediaType != header.ApplicationJSON {
		return mcpOAuthUpstreamTokenResponse{}, errors.New("upstream token exchange failed")
	}
	var value map[string]any
	if err := decodeStrictMCPOAuthObject(body, &value); err != nil {
		return mcpOAuthUpstreamTokenResponse{}, errors.New("invalid upstream token response")
	}
	accessToken, accessOK := value["access_token"].(string)
	tokenType, typeOK := value["token_type"].(string)
	refreshToken, _ := value["refresh_token"].(string)
	returnedScope, _ := value["scope"].(string)
	if returnedScope == "" {
		returnedScope = scope
	}
	expiresIn, ok := positiveOAuthSeconds(value["expires_in"])
	if !accessOK || accessToken == "" || !typeOK || !strings.EqualFold(tokenType, mcpOAuthBrokerTokenType) || !ok ||
		!oauthScopeSubset(returnedScope, scope) {
		return mcpOAuthUpstreamTokenResponse{}, errors.New("invalid upstream token response")
	}
	return mcpOAuthUpstreamTokenResponse{AccessToken: accessToken, RefreshToken: refreshToken, Scope: returnedScope, ExpiresIn: expiresIn}, nil
}

func (b *mcpOAuthBroker) validAuthorizationState(state mcpOAuthAuthorizationState) bool {
	return state.OrgID == b.spec.OrgID && state.APIID == b.spec.APIID && state.PublicIssuer == b.publicIssuer() &&
		state.PublicResource == b.config.PublicResource && state.UpstreamResource == b.config.UpstreamResource &&
		trustedMCPOAuthEndpoint(state.UpstreamIssuer, state.UpstreamToken, b.config.AllowInsecureLoopback) &&
		state.DownstreamClientID != "" && state.UpstreamClientID != "" && state.RedirectURI != "" &&
		validMCPOAuthPKCE(state.DownstreamChallenge) && validMCPOAuthPKCE(state.UpstreamVerifier)
}

func (b *mcpOAuthBroker) validDownstreamCode(code mcpOAuthDownstreamCode, clientID, redirectURI, resource string) bool {
	return code.OrgID == b.spec.OrgID && code.APIID == b.spec.APIID && code.PublicIssuer == b.publicIssuer() &&
		code.PublicResource == b.config.PublicResource && code.DownstreamClientID == clientID &&
		code.RedirectURI == redirectURI && resource == code.PublicResource && code.UpstreamResource == b.config.UpstreamResource
}

func (b *mcpOAuthBroker) validGrant(grant mcpOAuthTokenGrant, clientID, resource string) bool {
	return grant.OrgID == b.spec.OrgID && grant.APIID == b.spec.APIID && grant.PublicIssuer == b.publicIssuer() &&
		grant.PublicResource == b.config.PublicResource && grant.DownstreamClientID == clientID && resource == grant.PublicResource &&
		grant.UpstreamResource == b.config.UpstreamResource && grant.FamilyID != ""
}

func (b *mcpOAuthBroker) codeKey(value string) string {
	return mcpOAuthBrokerKey("code", b.spec.OrgID, b.spec.APIID, value)
}

func (b *mcpOAuthBroker) accessKey(value string) string {
	return mcpOAuthBrokerKey("access", b.spec.OrgID, b.spec.APIID, value)
}

func (b *mcpOAuthBroker) refreshKey(value string) string {
	return mcpOAuthBrokerKey("refresh", b.spec.OrgID, b.spec.APIID, value)
}

func (b *mcpOAuthBroker) refreshFamilyKey(value string) string {
	return mcpOAuthBrokerKey("refresh-family", b.spec.OrgID, b.spec.APIID, value)
}

func (b *mcpOAuthBroker) revokedFamilyKey(value string) string {
	return mcpOAuthBrokerKey("revoked-family", b.spec.OrgID, b.spec.APIID, value)
}

func singleOAuthValue(values url.Values, name string, nonempty bool) (string, bool) {
	items, ok := values[name]
	if !ok || len(items) != 1 || (nonempty && items[0] == "") {
		return "", false
	}
	return items[0], true
}

func optionalSingleOAuthValue(values url.Values, name string) (string, bool, bool) {
	items, present := values[name]
	if !present {
		return "", false, true
	}
	if len(items) != 1 || items[0] == "" {
		return "", true, false
	}
	return items[0], true, true
}

func exactOAuthFormFields(form url.Values, fields []string) bool {
	if len(form) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := form[field]; !ok {
			return false
		}
	}
	return true
}

func readOAuthForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	mediaType := strings.TrimSpace(strings.Split(r.Header.Get(header.ContentType), ";")[0])
	if mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return nil, errors.New("invalid token request content type")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpOAuthBrokerBodyMax))
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(body))
}

func positiveOAuthSeconds(value any) (time.Duration, bool) {
	var seconds int64
	switch typed := value.(type) {
	case float64:
		seconds = int64(typed)
		if float64(seconds) != typed {
			return 0, false
		}
	case json.Number:
		var err error
		seconds, err = typed.Int64()
		if err != nil {
			return 0, false
		}
	case string:
		var err error
		seconds, err = strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	if seconds <= 0 || seconds > int64((24*time.Hour)/time.Second) {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func oauthScopeSubset(returned, requested string) bool {
	requestedSet := map[string]struct{}{}
	for _, item := range strings.Fields(requested) {
		requestedSet[item] = struct{}{}
	}
	returnedItems := strings.Fields(returned)
	if len(returnedItems) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, item := range returnedItems {
		if _, ok := requestedSet[item]; !ok {
			return false
		}
		if _, duplicate := seen[item]; duplicate {
			return false
		}
		seen[item] = struct{}{}
	}
	return true
}

func validOAuthErrorCode(value string) bool {
	if value == "" || len(value) > mcpOAuthBrokerMaxErrorTextBytes {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char > 0x7e || char == '&' || char == '=' {
			return false
		}
	}
	return true
}

func brokerRedirect(target string, response url.Values) (string, error) {
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() {
		return "", fmt.Errorf("invalid redirect URI")
	}
	query := u.Query()
	for key, values := range response {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func mcpOAuthErrorNoStore(w http.ResponseWriter, status int, code string) {
	mcpOAuthJSONNoStore(w, status, map[string]string{"error": code})
}

func mcpOAuthJSONNoStore(w http.ResponseWriter, status int, value any) {
	mcpOAuthSetNoStore(w)
	mcpOAuthJSON(w, status, value)
}

func mcpOAuthSetNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

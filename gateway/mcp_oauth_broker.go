package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	internalhttputil "github.com/TykTechnologies/tyk/internal/httputil"
)

const (
	mcpOAuthBrokerStateTTL = 10 * time.Minute
	mcpOAuthBrokerBodyMax  = 64 << 10
)

type mcpOAuthBroker struct {
	gw     *Gateway
	spec   *APISpec
	config *apidef.MCPOAuthBrokerConfig
	store  mcpOAuthBrokerStore
	client *http.Client
}

type mcpOAuthClientMapping struct {
	OrgID                   string   `json:"org_id"`
	APIID                   string   `json:"api_id"`
	PublicIssuer            string   `json:"public_issuer"`
	PublicResource          string   `json:"public_resource"`
	UpstreamIssuer          string   `json:"upstream_issuer"`
	UpstreamResource        string   `json:"upstream_resource"`
	DownstreamClientID      string   `json:"downstream_client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	UpstreamClientID        string   `json:"upstream_client_id"`
	UpstreamTokenAuthMethod string   `json:"upstream_token_auth_method"`
}

type mcpOAuthAuthorizationState struct {
	OrgID               string `json:"org_id"`
	APIID               string `json:"api_id"`
	PublicIssuer        string `json:"public_issuer"`
	PublicResource      string `json:"public_resource"`
	UpstreamIssuer      string `json:"upstream_issuer"`
	UpstreamResource    string `json:"upstream_resource"`
	UpstreamAuthorize   string `json:"upstream_authorize"`
	UpstreamToken       string `json:"upstream_token"`
	UpstreamSupportsISS bool   `json:"upstream_supports_iss"`
	DownstreamClientID  string `json:"downstream_client_id"`
	UpstreamClientID    string `json:"upstream_client_id"`
	RedirectURI         string `json:"redirect_uri"`
	OriginalState       string `json:"original_state"`
	DownstreamChallenge string `json:"downstream_challenge"`
	UpstreamVerifier    string `json:"upstream_verifier"`
	Scope               string `json:"scope"`
}

func newMCPOAuthBroker(gw *Gateway, spec *APISpec) *mcpOAuthBroker {
	return &mcpOAuthBroker{
		gw: gw, spec: spec, config: spec.MCP.OAuthBroker,
		store: newRedisMCPOAuthBrokerStore(gw), client: http.DefaultClient,
	}
}

func (b *mcpOAuthBroker) publicIssuer() string {
	return b.config.PublicOrigin + mcpASProxyPathPrefix + b.spec.APIID
}

func (b *mcpOAuthBroker) callbackURL() string { return b.publicIssuer() + "/callback" }

func (b *mcpOAuthBroker) clientKey(clientID string) string {
	return mcpOAuthBrokerKey("client", b.spec.OrgID, b.spec.APIID, clientID)
}

func mcpOAuthBrokerKey(kind string, parts ...string) string {
	// Redis Cluster requires every key touched by an atomic Lua operation to
	// share a hash slot. Broker records are therefore colocated per org/API,
	// using a hashed tag so neither identity appears in the storage key.
	scope := sha256.New()
	for index := 0; index < 2 && index < len(parts); index++ {
		_, _ = scope.Write([]byte{0})
		_, _ = scope.Write([]byte(parts[index]))
	}
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return "{" + hex.EncodeToString(scope.Sum(nil)) + "}:" + kind + ":" + hex.EncodeToString(hash.Sum(nil))
}

func randomMCPOAuthValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func mcpOAuthPKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (b *mcpOAuthBroker) resolveUpstream(ctx context.Context) (map[string]any, string, error) {
	doc, err := b.gw.upstreamPRMDoc(ctx, b.spec)
	if err != nil {
		return nil, "", err
	}
	if doc.Resource() != b.config.UpstreamResource {
		return nil, "", errors.New("upstream PRM resource does not exactly match configured upstream resource")
	}
	servers, ok := doc.Raw["authorization_servers"].([]any)
	if !ok || len(servers) == 0 {
		return nil, "", errors.New("upstream PRM has no authorization server")
	}
	issuer, ok := servers[0].(string)
	if !ok || issuer == "" {
		return nil, "", errors.New("upstream PRM authorization server is invalid")
	}
	metadata, err := fetchUpstreamASMetadataWithClient(ctx, b.client, issuer, b.config.AllowInsecureLoopback)
	if err != nil {
		return nil, "", err
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint"} {
		endpoint, ok := metadata[field].(string)
		if !ok || !trustedMCPOAuthEndpoint(issuer, endpoint, b.config.AllowInsecureLoopback) {
			return nil, "", fmt.Errorf("upstream metadata contains invalid %s", field)
		}
	}
	return metadata, issuer, nil
}

func trustedMCPOAuthEndpoint(issuer, endpoint string, allowInsecureLoopback bool) bool {
	issuerURL, issuerErr := url.Parse(issuer)
	endpointURL, endpointErr := url.Parse(endpoint)
	if issuerErr != nil || endpointErr != nil || !endpointURL.IsAbs() || endpointURL.User != nil ||
		endpointURL.RawQuery != "" || endpointURL.Fragment != "" ||
		issuerURL.Scheme != endpointURL.Scheme || issuerURL.Host != endpointURL.Host {
		return false
	}
	return endpointURL.Scheme == "https" ||
		(endpointURL.Scheme == "http" && allowInsecureLoopback && isLoopbackURL(endpointURL))
}

func (b *mcpOAuthBroker) metadataHandler(w http.ResponseWriter, r *http.Request) {
	if !b.validPublicRequest(r) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	metadata, _, err := b.resolveUpstream(r.Context())
	if err != nil {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	issuer := b.publicIssuer()
	result := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/authorize",
		"token_endpoint":                                 issuer + "/token",
		"registration_endpoint":                          issuer + "/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
	}
	for _, field := range []string{"scopes_supported", "service_documentation", "op_policy_uri", "op_tos_uri"} {
		if value, ok := metadata[field]; ok {
			result[field] = value
		}
	}
	mcpOAuthJSON(w, http.StatusOK, result)
}

func (b *mcpOAuthBroker) registrationHandler(w http.ResponseWriter, r *http.Request) {
	mcpOAuthSetNoStore(w)
	if !b.validPublicRequest(r) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(header.ContentType))
	if err != nil || mediaType != header.ApplicationJSON {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpOAuthBrokerBodyMax))
	if err != nil {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	var registration map[string]any
	if err := decodeStrictMCPOAuthObject(body, &registration); err != nil {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	for name := range registration {
		for _, forbidden := range []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri"} {
			if strings.EqualFold(name, forbidden) {
				mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
				return
			}
		}
	}
	redirects, ok := stringSlice(registration["redirect_uris"])
	method, methodOK := registration["token_endpoint_auth_method"].(string)
	if !ok || !methodOK || method != "none" || !validMCPOAuthRedirects(redirects) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	if !validOptionalMCPOAuthRegistrationValues(registration, "response_types", []string{"code"}, true) ||
		!validOptionalMCPOAuthRegistrationValues(registration, "grant_types", []string{"authorization_code", "refresh_token"}, false) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	metadata, upstreamIssuer, err := b.resolveUpstream(r.Context())
	if err != nil {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	registrationEndpoint, ok := metadata["registration_endpoint"].(string)
	if !ok || !trustedMCPOAuthEndpoint(upstreamIssuer, registrationEndpoint, b.config.AllowInsecureLoopback) {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	upstreamRegistration := mapsClone(registration)
	upstreamRegistration["redirect_uris"] = []string{b.callbackURL()}
	upstreamRegistration["token_endpoint_auth_method"] = "none"
	upstreamRegistration["response_types"] = []string{"code"}
	upstreamRegistration["grant_types"] = []string{"authorization_code", "refresh_token"}
	encoded, err := json.Marshal(upstreamRegistration)
	if err != nil {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	response, err := b.doUpstream(r.Context(), http.MethodPost, registrationEndpoint, "application/json", encoded)
	if err != nil {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, mcpOAuthBrokerBodyMax+1))
	if err != nil || len(responseBody) > mcpOAuthBrokerBodyMax || response.StatusCode/100 != 2 {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	var upstream map[string]any
	if err := decodeStrictMCPOAuthObject(responseBody, &upstream); err != nil {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	upstreamClientID, ok := upstream["client_id"].(string)
	upstreamMethod, _ := upstream["token_endpoint_auth_method"].(string)
	registrationClientURI, registrationClientURIOK := upstream["registration_client_uri"].(string)
	registrationAccessToken, registrationAccessTokenOK := upstream["registration_access_token"].(string)
	if !ok || upstreamClientID == "" || (upstreamMethod != "" && upstreamMethod != "none") ||
		upstream["client_secret"] != nil || !registrationClientURIOK || !registrationAccessTokenOK ||
		!validMCPOAuthRegistrationManagementEndpoint(registrationEndpoint, registrationClientURI,
			b.config.AllowInsecureLoopback) || !validMCPOAuthBearerValue(registrationAccessToken) {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	downstreamClientID, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	mapping := mcpOAuthClientMapping{
		OrgID: b.spec.OrgID, APIID: b.spec.APIID, PublicIssuer: b.publicIssuer(),
		PublicResource: b.config.PublicResource, UpstreamIssuer: upstreamIssuer,
		UpstreamResource: b.config.UpstreamResource, DownstreamClientID: downstreamClientID,
		RedirectURIs: slices.Clone(redirects), UpstreamClientID: upstreamClientID,
		UpstreamTokenAuthMethod: "none",
	}
	if err := b.putRecord(r.Context(), b.clientKey(downstreamClientID), mapping, 0); err != nil {
		if rollbackErr := b.rollbackUpstreamRegistration(r.Context(), registrationClientURI, registrationAccessToken); rollbackErr != nil {
			log.WithField("api_id", b.spec.APIID).WithField("org_id", b.spec.OrgID).
				Warn("MCP OAuth upstream registration rollback failed")
		}
		mcpOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	result := mapsClone(registration)
	result["client_id"] = downstreamClientID
	result["redirect_uris"] = redirects
	result["token_endpoint_auth_method"] = "none"
	result["response_types"] = []string{"code"}
	result["grant_types"] = []string{"authorization_code", "refresh_token"}
	mcpOAuthJSON(w, http.StatusCreated, result)
}

func validMCPOAuthRegistrationManagementEndpoint(registrationEndpoint, managementEndpoint string, allowInsecureLoopback bool) bool {
	if !trustedMCPOAuthEndpoint(registrationEndpoint, managementEndpoint, allowInsecureLoopback) {
		return false
	}
	parsed, err := url.Parse(managementEndpoint)
	if err != nil || parsed.Opaque != "" || parsed.ForceQuery {
		return false
	}
	// Require the exact canonical serialization returned by the registration
	// response. The broker never resolves or accepts a caller-supplied target.
	return parsed.String() == managementEndpoint
}

func validMCPOAuthBearerValue(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char <= 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func (b *mcpOAuthBroker) rollbackUpstreamRegistration(ctx context.Context, managementEndpoint, accessToken string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, managementEndpoint, nil)
	if err != nil {
		return errors.New("invalid upstream registration rollback request")
	}
	request.Header.Set(header.Accept, header.ApplicationJSON)
	request.Header.Set(header.Authorization, "Bearer "+accessToken)
	client := *b.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 10 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return errors.New("upstream registration rollback request failed")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, mcpOAuthBrokerBodyMax+1))
	if readErr != nil || len(body) > mcpOAuthBrokerBodyMax || response.StatusCode/100 != 2 {
		return errors.New("upstream registration rollback was rejected")
	}
	return nil
}

func (b *mcpOAuthBroker) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	mcpOAuthSetNoStore(w)
	if !b.validPublicRequest(r) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	query := r.URL.Query()
	for _, field := range []string{"response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "resource", "scope"} {
		if len(query[field]) != 1 || query.Get(field) == "" {
			mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" ||
		!validMCPOAuthPKCE(query.Get("code_challenge")) || query.Get("resource") != b.config.PublicResource {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var mapping mcpOAuthClientMapping
	found, err := b.getRecord(r.Context(), b.clientKey(query.Get("client_id")), &mapping)
	if err != nil {
		mcpOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !found || !b.validMapping(mapping, query.Get("redirect_uri")) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	metadata, upstreamIssuer, err := b.resolveUpstream(r.Context())
	if err != nil || upstreamIssuer != mapping.UpstreamIssuer {
		mcpOAuthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	if !metadataSupportsMCPOAuthScope(metadata, query.Get("scope")) {
		mcpOAuthError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	upstreamState, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	upstreamVerifier, err := randomMCPOAuthValue()
	if err != nil {
		mcpOAuthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	upstreamAuthorize := metadata["authorization_endpoint"].(string)
	upstreamToken := metadata["token_endpoint"].(string)
	state := mcpOAuthAuthorizationState{
		OrgID: b.spec.OrgID, APIID: b.spec.APIID, PublicIssuer: b.publicIssuer(), PublicResource: b.config.PublicResource,
		UpstreamIssuer: upstreamIssuer, UpstreamResource: b.config.UpstreamResource,
		UpstreamAuthorize: upstreamAuthorize, UpstreamToken: upstreamToken,
		UpstreamSupportsISS: metadata["authorization_response_iss_parameter_supported"] == true,
		DownstreamClientID:  mapping.DownstreamClientID, UpstreamClientID: mapping.UpstreamClientID,
		RedirectURI: query.Get("redirect_uri"), OriginalState: query.Get("state"),
		DownstreamChallenge: query.Get("code_challenge"), UpstreamVerifier: upstreamVerifier, Scope: query.Get("scope"),
	}
	if err := b.putRecord(r.Context(), mcpOAuthBrokerKey("state", b.spec.OrgID, b.spec.APIID, upstreamState), state, mcpOAuthBrokerStateTTL); err != nil {
		mcpOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	target, _ := url.Parse(upstreamAuthorize)
	upstreamQuery := target.Query()
	upstreamQuery.Set("response_type", "code")
	upstreamQuery.Set("client_id", mapping.UpstreamClientID)
	upstreamQuery.Set("redirect_uri", b.callbackURL())
	upstreamQuery.Set("state", upstreamState)
	upstreamQuery.Set("code_challenge", mcpOAuthPKCEChallenge(upstreamVerifier))
	upstreamQuery.Set("code_challenge_method", "S256")
	upstreamQuery.Set("resource", b.config.UpstreamResource)
	upstreamQuery.Set("scope", query.Get("scope"))
	target.RawQuery = upstreamQuery.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (b *mcpOAuthBroker) validMapping(mapping mcpOAuthClientMapping, redirectURI string) bool {
	return mapping.OrgID == b.spec.OrgID && mapping.APIID == b.spec.APIID &&
		mapping.PublicIssuer == b.publicIssuer() && mapping.PublicResource == b.config.PublicResource &&
		mapping.UpstreamResource == b.config.UpstreamResource && slices.Contains(mapping.RedirectURIs, redirectURI)
}

func (b *mcpOAuthBroker) validPublicRequest(r *http.Request) bool {
	origin, err := internalhttputil.ExternalOriginWithTrustedProxies(r, b.spec.mcpTrustedProxyPrefixes)
	return err == nil && origin == b.config.PublicOrigin
}

func metadataSupportsMCPOAuthScope(metadata map[string]any, requested string) bool {
	scopes, ok := metadata["scopes_supported"].([]any)
	if !ok {
		return false
	}
	requestedScopes := strings.Split(requested, " ")
	if len(requestedScopes) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(requestedScopes))
	for _, scope := range requestedScopes {
		if scope == "" {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
		if !slices.ContainsFunc(scopes, func(value any) bool { return value == scope }) {
			return false
		}
	}
	return true
}

func (b *mcpOAuthBroker) doUpstream(ctx context.Context, method, target, contentType string, body []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set(header.Accept, header.ApplicationJSON)
	if contentType != "" {
		request.Header.Set(header.ContentType, contentType)
	}
	client := *b.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 10 * time.Second
	return client.Do(request)
}

func validMCPOAuthRedirects(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		u, err := url.Parse(value)
		if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
			return false
		}
		for _, reserved := range []string{"code", "error", "error_description", "error_uri", "state", "iss"} {
			if _, present := u.Query()[reserved]; present {
				return false
			}
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validMCPOAuthPKCE(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-._~", char)) {
			return false
		}
	}
	return true
}

func stringSlice(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok || len(raw) == 0 {
		return nil, false
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func validOptionalMCPOAuthRegistrationValues(registration map[string]any, field string, allowed []string, requireAll bool) bool {
	value, present := registration[field]
	if !present {
		return true
	}
	values, ok := stringSlice(value)
	if !ok {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, item := range values {
		if !slices.Contains(allowed, item) {
			return false
		}
		if _, duplicate := seen[item]; duplicate {
			return false
		}
		seen[item] = struct{}{}
	}
	if requireAll {
		return len(seen) == len(allowed)
	}
	return slices.Contains(values, "authorization_code")
}

func mapsClone(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func decodeStrictMCPOAuthObject(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("expected JSON object")
	}
	seenExact := make(map[string]struct{})
	seenSecurity := make(map[string]struct{})
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok {
			return errors.New("invalid JSON object key")
		}
		if _, duplicate := seenExact[name]; duplicate {
			return errors.New("duplicate JSON object key")
		}
		seenExact[name] = struct{}{}
		for _, securityField := range []string{
			"redirect_uris", "token_endpoint_auth_method", "client_id", "client_secret",
			"registration_access_token", "registration_client_uri",
			"access_token", "refresh_token", "token_type", "expires_in", "scope",
		} {
			if strings.EqualFold(name, securityField) {
				if _, duplicate := seenSecurity[securityField]; duplicate {
					return errors.New("duplicate JSON security field")
				}
				seenSecurity[securityField] = struct{}{}
				break
			}
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return json.Unmarshal(body, target)
}

func mcpOAuthError(w http.ResponseWriter, status int, code string) {
	mcpOAuthJSON(w, status, map[string]string{"error": code})
}

func mcpOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

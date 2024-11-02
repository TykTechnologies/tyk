package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/sirupsen/logrus"
	oauth2clientcredentials "golang.org/x/oauth2/clientcredentials"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	UpstreamOAuthErrorEventName = "UpstreamOAuthError"
	UpstreamOAuthMiddlewareName = "UpstreamOAuth"
)

type OAuthHeaderProvider interface {
	// getOAuthToken returns the OAuth token for the request.
	getOAuthToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error)
	getHeaderName(OAuthSpec *UpstreamOAuth) string
	headerEnabled(OAuthSpec *UpstreamOAuth) bool
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

type PasswordOAuthProvider struct{}

func newUpstreamOAuthClientCredentialsCache(connectionHandler *storage.ConnectionHandler) UpstreamOAuthCache {
	return &upstreamOAuthClientCredentialsCache{RedisCluster: storage.RedisCluster{KeyPrefix: "upstreamOAuthCC-", ConnectionHandler: connectionHandler}}
}

func newUpstreamOAuthPasswordCache(connectionHandler *storage.ConnectionHandler) UpstreamOAuthCache {
	return &upstreamOAuthPasswordCache{RedisCluster: storage.RedisCluster{KeyPrefix: "upstreamOAuthPW-", ConnectionHandler: connectionHandler}}
}

type upstreamOAuthClientCredentialsCache struct {
	storage.RedisCluster
}

type upstreamOAuthPasswordCache struct {
	storage.RedisCluster
}

func (cache *upstreamOAuthPasswordCache) getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	cacheKey := generatePasswordOAuthCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	tokenData, err := retryGetKeyAndLock(cacheKey, &cache.RedisCluster)
	if err != nil {
		return "", err
	}

	if tokenData != "" {
		tokenContents, err := unmarshalTokenData(tokenData)
		if err != nil {
			return "", err
		}
		decryptedToken := decrypt(getPaddedSecret(OAuthSpec.Gw.GetConfig().Secret), tokenContents.Token)
		setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata, tokenContents.ExtraMetadata)
		return decryptedToken, nil
	}

	token, err := cache.obtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := encrypt(getPaddedSecret(OAuthSpec.Gw.GetConfig().Secret), token.AccessToken)
	tokenDataBytes, err := createTokenDataBytes(encryptedToken, token, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata)
	if err != nil {
		return "", err
	}
	metadataMap := buildMetadataMap(token, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata)
	setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata, metadataMap)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cacheKey, string(tokenDataBytes), ttl, &cache.RedisCluster); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func (cache *upstreamOAuthPasswordCache) obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (*oauth2.Token, error) {
	cfg := newOAuth2PasswordConfig(OAuthSpec)

	token, err := cfg.PasswordCredentialsToken(ctx, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Username, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Password)
	if err != nil {
		return &oauth2.Token{}, err
	}

	return token, nil
}

type UpstreamOAuthCache interface {
	// getToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error)
	// obtainToken issues a request to obtain the token from the OAuth provider.
	obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (*oauth2.Token, error)
}

// UpstreamOAuth is a middleware that will do basic authentication for upstream connections.
// UpstreamOAuth middleware is only supported in Tyk OAS API definitions.
type UpstreamOAuth struct {
	*BaseMiddleware
}

// Name returns the name of middleware.
func (OAuthSpec *UpstreamOAuth) Name() string {
	return UpstreamOAuthMiddlewareName
}

// EnabledForSpec returns true if the middleware is enabled based on API Spec.
func (OAuthSpec *UpstreamOAuth) EnabledForSpec() bool {
	if !OAuthSpec.Spec.UpstreamAuth.Enabled {
		return false
	}

	if !OAuthSpec.Spec.UpstreamAuth.OAuth.Enabled {
		return false
	}

	return true
}

// ProcessRequest will inject basic auth info into request context so that it can be used during reverse proxy.
func (OAuthSpec *UpstreamOAuth) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	oauthConfig := OAuthSpec.Spec.UpstreamAuth.OAuth

	upstreamOAuthProvider := UpstreamOAuthProvider{
		HeaderName: header.Authorization,
	}

	provider, err := getOAuthHeaderProvider(oauthConfig)
	if err != nil {
		return fmt.Errorf("failed to get OAuth header provider: %w", err), http.StatusInternalServerError
	}

	payload, err := provider.getOAuthToken(r, OAuthSpec)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err), http.StatusInternalServerError
	}

	upstreamOAuthProvider.AuthValue = payload
	headerName := provider.getHeaderName(OAuthSpec)
	if headerName != "" {
		upstreamOAuthProvider.HeaderName = headerName
	}

	if provider.headerEnabled(OAuthSpec) {
		headerName := provider.getHeaderName(OAuthSpec)
		if headerName != "" {
			upstreamOAuthProvider.HeaderName = headerName
		}
	}

	httputil.SetUpstreamAuth(r, upstreamOAuthProvider)
	return nil, http.StatusOK
}

func getOAuthHeaderProvider(oauthConfig apidef.UpstreamOAuth) (OAuthHeaderProvider, error) {
	if !oauthConfig.IsEnabled() {
		return nil, fmt.Errorf("upstream OAuth is not enabled")
	}

	switch {
	case len(oauthConfig.AllowedAuthorizeTypes) == 0:
		return nil, fmt.Errorf("no OAuth configuration selected")
	case len(oauthConfig.AllowedAuthorizeTypes) > 1:
		return nil, fmt.Errorf("both client credentials and password authentication are provided")
	case oauthConfig.AllowedAuthorizeTypes[0] == apidef.OAuthAuthorizationTypeClientCredentials:
		return &ClientCredentialsOAuthProvider{}, nil
	case oauthConfig.AllowedAuthorizeTypes[0] == apidef.OAuthAuthorizationTypePassword:
		return &PasswordOAuthProvider{}, nil
	default:
		return nil, fmt.Errorf("no valid OAuth configuration provided")
	}
}

func (p *PerAPIClientCredentialsOAuthProvider) getOAuthHeaderValue(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	oauthConfig := OAuthSpec.Spec.UpstreamAuth.OAuth

	if oauthConfig.ClientCredentials.TokenProvider == nil {
		cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)
		tokenSource := cfg.TokenSource(r.Context())

		oauthConfig.ClientCredentials.TokenProvider = tokenSource
	}

	oauthToken, err := oauthConfig.ClientCredentials.TokenProvider.Token()
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	payload := fmt.Sprintf("Bearer %s", oauthToken.AccessToken)
	return payload, nil
}

func handleOAuthError(r *http.Request, OAuthSpec *UpstreamOAuth, err error) (string, error) {
	OAuthSpec.emitUpstreamOAuthEvent(r, UpstreamOAuthErrorEventName, err.Error(), OAuthSpec.Spec.APIID)
	return "", err
}

func (p *ClientCredentialsOAuthProvider) getOAuthToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	if OAuthSpec.Gw.UpstreamOAuthCache == nil {
		OAuthSpec.Gw.UpstreamOAuthCache = newUpstreamOAuthClientCredentialsCache(OAuthSpec.Gw.StorageConnectionHandler)
	}

	token, err := OAuthSpec.Gw.UpstreamOAuthCache.getToken(r, OAuthSpec)
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func (p *ClientCredentialsOAuthProvider) headerEnabled(OAuthSpec *UpstreamOAuth) bool {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Enabled
}

func (p *ClientCredentialsOAuthProvider) getHeaderName(OAuthSpec *UpstreamOAuth) string {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Name
}

func (p *PasswordOAuthProvider) getOAuthToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	if OAuthSpec.Gw.UpstreamOAuthCache == nil {
		OAuthSpec.Gw.UpstreamOAuthCache = newUpstreamOAuthPasswordCache(OAuthSpec.Gw.StorageConnectionHandler)
	}

	token, err := OAuthSpec.Gw.UpstreamOAuthCache.getToken(r, OAuthSpec)
	if err != nil {
		return handleOAuthError(r, OAuthSpec, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func (p *PasswordOAuthProvider) getHeaderName(OAuthSpec *UpstreamOAuth) string {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Header.Name
}

func (p *PasswordOAuthProvider) headerEnabled(OAuthSpec *UpstreamOAuth) bool {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Header.Enabled
}

func generatePasswordOAuthCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	key := fmt.Sprintf(
		"%s|%s|%s|%s",
		apiId,
		config.PasswordAuthentication.ClientID,
		config.PasswordAuthentication.ClientSecret,
		strings.Join(config.PasswordAuthentication.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

func generateClientCredentialsCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	key := fmt.Sprintf(
		"%s|%s|%s|%s",
		apiId,
		config.ClientCredentials.ClientID,
		config.ClientCredentials.TokenURL,
		strings.Join(config.ClientCredentials.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

type TokenData struct {
	Token         string                 `json:"token"`
	ExtraMetadata map[string]interface{} `json:"extra_metadata"`
}

func (cache *upstreamOAuthClientCredentialsCache) getToken(r *http.Request, OAuthSpec *UpstreamOAuth) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	tokenData, err := retryGetKeyAndLock(cacheKey, &cache.RedisCluster)
	if err != nil {
		return "", err
	}

	if tokenData != "" {
		tokenContents, err := unmarshalTokenData(tokenData)
		if err != nil {
			return "", err
		}
		decryptedToken := decrypt(getPaddedSecret(OAuthSpec.Gw.GetConfig().Secret), tokenContents.Token)
		setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata, tokenContents.ExtraMetadata)
		return decryptedToken, nil
	}

	token, err := cache.obtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := encrypt(getPaddedSecret(OAuthSpec.Gw.GetConfig().Secret), token.AccessToken)
	tokenDataBytes, err := createTokenDataBytes(encryptedToken, token, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata)
	if err != nil {
		return "", err
	}
	metadataMap := buildMetadataMap(token, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata)
	setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata, metadataMap)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cacheKey, string(tokenDataBytes), ttl, &cache.RedisCluster); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func createTokenDataBytes(encryptedToken string, token *oauth2.Token, extraMetadataKeys []string) ([]byte, error) {
	td := TokenData{
		Token:         encryptedToken,
		ExtraMetadata: buildMetadataMap(token, extraMetadataKeys),
	}
	return json.Marshal(td)
}

func unmarshalTokenData(tokenData string) (TokenData, error) {
	var tokenContents TokenData
	err := json.Unmarshal([]byte(tokenData), &tokenContents)
	if err != nil {
		return TokenData{}, fmt.Errorf("failed to unmarshal token data: %w", err)
	}
	return tokenContents, nil
}

func buildMetadataMap(token *oauth2.Token, extraMetadataKeys []string) map[string]interface{} {
	metadataMap := make(map[string]interface{})
	for _, key := range extraMetadataKeys {
		if val := token.Extra(key); val != "" && val != nil {
			metadataMap[key] = val
		}
	}
	return metadataMap
}

func setExtraMetadata(r *http.Request, keyList []string, token map[string]interface{}) {
	contextDataObject := ctxGetData(r)
	if contextDataObject == nil {
		contextDataObject = make(map[string]interface{})
	}
	for _, key := range keyList {
		if val, ok := token[key]; ok && val != "" {
			contextDataObject[key] = val
		}
	}
	ctxSetData(r, contextDataObject)
}

func retryGetKeyAndLock(cacheKey string, cache *storage.RedisCluster) (string, error) {
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	var tokenData string
	var err error

	for i := 0; i < maxRetries; i++ {
		tokenData, err = cache.GetKey(cacheKey)
		if err == nil {
			return tokenData, nil
		}

		lockKey := cacheKey + ":lock"
		ok, err := cache.Lock(lockKey, time.Second*5)
		if err == nil && ok {
			return "", nil
		}

		time.Sleep(retryDelay)
	}

	return "", fmt.Errorf("failed to acquire lock after retries: %v", err)
}

func newOAuth2ClientCredentialsConfig(OAuthSpec *UpstreamOAuth) oauth2clientcredentials.Config {
	return oauth2clientcredentials.Config{
		ClientID:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientID,
		ClientSecret: OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientSecret,
		TokenURL:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.TokenURL,
		Scopes:       OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Scopes,
	}
}

func newOAuth2PasswordConfig(OAuthSpec *UpstreamOAuth) oauth2.Config {
	return oauth2.Config{
		ClientID:     OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ClientID,
		ClientSecret: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.TokenURL,
		},
		Scopes: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Scopes,
	}
}

func (cache *upstreamOAuthClientCredentialsCache) obtainToken(ctx context.Context, OAuthSpec *UpstreamOAuth) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)

	tokenSource := cfg.TokenSource(ctx)
	oauthToken, err := tokenSource.Token()
	if err != nil {
		return &oauth2.Token{}, err
	}

	return oauthToken, nil
}

func setTokenInCache(cacheKey string, token string, ttl time.Duration, cache *storage.RedisCluster) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(oauthTokenExpiry.Sub(time.Now()).Seconds()))
}

// UpstreamOAuthProvider implements upstream auth provider.
type UpstreamOAuthProvider struct {
	// HeaderName is the header name to be used to fill upstream auth with.
	HeaderName string
	// AuthValue is the value of auth header.
	AuthValue string
}

// Fill sets the request's HeaderName with AuthValue
func (u UpstreamOAuthProvider) Fill(r *http.Request) {
	if r.Header.Get(u.HeaderName) != "" {
		log.WithFields(logrus.Fields{
			"header": u.HeaderName,
		}).Info("Authorization header conflict detected: Client header overwritten by Gateway upstream authentication header.")
	}
	r.Header.Set(u.HeaderName, u.AuthValue)
}

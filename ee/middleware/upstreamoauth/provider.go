package upstreamoauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	oauth2clientcredentials "golang.org/x/oauth2/clientcredentials"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/storage"
)

// Provider implements upstream auth provider.
type Provider struct {
	// Logger is the logger to be used.
	Logger *logrus.Entry
	// HeaderName is the header name to be used to fill upstream auth with.
	HeaderName string
	// AuthValue is the value of auth header.
	AuthValue string
}

// Fill sets the request's HeaderName with AuthValue
func (u Provider) Fill(r *http.Request) {
	if r.Header.Get(u.HeaderName) != "" {
		u.Logger.WithFields(logrus.Fields{
			"header": u.HeaderName,
		}).Info("Authorization header conflict detected: Client header overwritten by Gateway upstream authentication header.")
	}
	r.Header.Set(u.HeaderName, u.AuthValue)
}

type OAuthHeaderProvider interface {
	// getOAuthToken returns the OAuth token for the request.
	getOAuthToken(r *http.Request, OAuthSpec *Middleware) (string, error)
	// getHeaderName returns the header name for the OAuth token.
	getHeaderName(OAuthSpec *Middleware) string
	//
	headerEnabled(OAuthSpec *Middleware) bool
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
	case oauthConfig.AllowedAuthorizeTypes[0] == ClientCredentialsAuthorizeType:
		return &ClientCredentialsOAuthProvider{}, nil
	case oauthConfig.AllowedAuthorizeTypes[0] == PasswordAuthorizeType:
		return &PasswordOAuthProvider{}, nil
	default:
		return nil, fmt.Errorf("no valid OAuth configuration provided")
	}
}

func (p *ClientCredentialsOAuthProvider) getOAuthToken(r *http.Request, mw *Middleware) (string, error) {
	client := UpstreamOAuthClientCredentialsClient{mw.clientCredentialsStorageHandler}
	token, err := client.GetToken(r, mw)
	if err != nil {
		return handleOAuthError(r, mw, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func handleOAuthError(r *http.Request, mw *Middleware, err error) (string, error) {
	mw.EmitUpstreamOAuthEvent(r, ErrorEventName, err.Error(), mw.Spec.APIID)
	return "", err
}

func (p *ClientCredentialsOAuthProvider) getHeaderName(OAuthSpec *Middleware) string {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Name
}

func (p *ClientCredentialsOAuthProvider) headerEnabled(OAuthSpec *Middleware) bool {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Enabled
}

type UpstreamOAuthCache interface {
	// GetToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	GetToken(r *http.Request, OAuthSpec *Middleware) (string, error)
	// ObtainToken issues a request to obtain the token from the OAuth provider.
	ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error)
}

func (cache *UpstreamOAuthClientCredentialsClient) GetToken(r *http.Request, OAuthSpec *Middleware) (string, error) {
	cacheKey := generateClientCredentialsCacheKey(OAuthSpec.Spec.UpstreamAuth.OAuth, OAuthSpec.Spec.APIID)

	tokenString, err := retryGetKeyAndLock(cacheKey, cache.RedisCluster)
	if err != nil {
		return "", err
	}

	if tokenString != "" {
		decryptedToken := crypto.Decrypt(crypto.GetPaddedString(OAuthSpec.Gw.GetConfig().Secret), tokenString)
		return decryptedToken, nil
	}

	token, err := cache.ObtainToken(r.Context(), OAuthSpec)
	if err != nil {
		return "", err
	}

	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(OAuthSpec.Gw.GetConfig().Secret), token.AccessToken)
	setExtraMetadata(r, OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ExtraMetadata, token)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cacheKey, encryptedToken, ttl, cache.RedisCluster); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func setTokenInCache(cacheKey string, token string, ttl time.Duration, cache *storage.RedisCluster) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(oauthTokenExpiry.Sub(time.Now()).Seconds()))
}

func (cache *UpstreamOAuthClientCredentialsClient) ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error) {
	cfg := newOAuth2ClientCredentialsConfig(OAuthSpec)

	tokenSource := cfg.TokenSource(ctx)
	oauthToken, err := tokenSource.Token()
	if err != nil {
		return &oauth2.Token{}, err
	}

	return oauthToken, nil
}

func (cache *UpstreamOAuthPasswordClient) ObtainToken(ctx context.Context, OAuthSpec *Middleware) (*oauth2.Token, error) {
	cfg := newOAuth2PasswordConfig(OAuthSpec)

	token, err := cfg.PasswordCredentialsToken(ctx, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Username, OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Password)
	if err != nil {
		return &oauth2.Token{}, err
	}

	return token, nil
}

func newOAuth2ClientCredentialsConfig(OAuthSpec *Middleware) oauth2clientcredentials.Config {
	return oauth2clientcredentials.Config{
		ClientID:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientID,
		ClientSecret: OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.ClientSecret,
		TokenURL:     OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.TokenURL,
		Scopes:       OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Scopes,
	}
}

func newOAuth2PasswordConfig(OAuthSpec *Middleware) oauth2.Config {
	return oauth2.Config{
		ClientID:     OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ClientID,
		ClientSecret: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.TokenURL,
		},
		Scopes: OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Scopes,
	}
}

type UpstreamOAuthClientCredentialsClient struct {
	*storage.RedisCluster
}

type UpstreamOAuthPasswordClient struct {
	*storage.RedisCluster
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

func retryGetKeyAndLock(cacheKey string, cache *storage.RedisCluster) (string, error) {
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	var token string
	var err error

	for i := 0; i < maxRetries; i++ {
		token, err = cache.GetKey(cacheKey)
		if err == nil {
			return token, nil
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

func setExtraMetadata(r *http.Request, keyList []string, token *oauth2.Token) {
	contextDataObject := ctxGetData(r)
	if contextDataObject == nil {
		contextDataObject = make(map[string]interface{})
	}
	for _, key := range keyList {
		val := token.Extra(key)
		if val != "" {
			contextDataObject[key] = val
		}
	}
	ctxSetData(r, contextDataObject)
}

// EventUpstreamOAuthMeta is the metadata structure for an upstream OAuth event
type EventUpstreamOAuthMeta struct {
	model.EventMetaDefault
	APIID string
}

func (p *PasswordOAuthProvider) getOAuthToken(r *http.Request, mw *Middleware) (string, error) {
	client := UpstreamOAuthPasswordClient{RedisCluster: mw.passwordStorageHandler}
	token, err := client.GetToken(r, mw)
	if err != nil {
		return handleOAuthError(r, mw, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func (p *PasswordOAuthProvider) getHeaderName(OAuthSpec *Middleware) string {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Header.Name
}

func (p *PasswordOAuthProvider) headerEnabled(OAuthSpec *Middleware) bool {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.PasswordAuthentication.Header.Enabled
}

func (cache *UpstreamOAuthPasswordClient) GetToken(r *http.Request, mw *Middleware) (string, error) {
	cacheKey := generatePasswordOAuthCacheKey(mw.Spec.UpstreamAuth.OAuth, mw.Spec.APIID)

	tokenString, err := retryGetKeyAndLock(cacheKey, cache.RedisCluster)
	if err != nil {
		return "", err
	}

	if tokenString != "" {
		decryptedToken := crypto.Decrypt(crypto.GetPaddedString(mw.Gw.GetConfig().Secret), tokenString)
		return decryptedToken, nil
	}

	token, err := cache.ObtainToken(r.Context(), mw)
	if err != nil {
		return "", err
	}

	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(mw.Gw.GetConfig().Secret), token.AccessToken)
	setExtraMetadata(r, mw.Spec.UpstreamAuth.OAuth.PasswordAuthentication.ExtraMetadata, token)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cacheKey, encryptedToken, ttl, cache.RedisCluster); err != nil {
		return "", err
	}

	return token.AccessToken, nil
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

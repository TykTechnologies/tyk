package upstreamoauth

import (
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
	"github.com/TykTechnologies/tyk/internal/model"
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
	getOAuthToken(r *http.Request, mw *Middleware) (string, error)
	// getHeaderName returns the header name for the OAuth token.
	getHeaderName(mw *Middleware) string
	//
	headerEnabled(mw *Middleware) bool
}

func NewOAuthHeaderProvider(oauthConfig apidef.UpstreamOAuth) (OAuthHeaderProvider, error) {
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
	client := ClientCredentialsClient{mw}
	token, err := client.GetToken(r)
	if err != nil {
		return handleOAuthError(r, mw, err)
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func handleOAuthError(r *http.Request, mw *Middleware, err error) (string, error) {
	mw.FireEvent(r, ErrorEventName, err.Error(), mw.Spec.APIID)
	return "", err
}

func (p *ClientCredentialsOAuthProvider) getHeaderName(OAuthSpec *Middleware) string {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Name
}

func (p *ClientCredentialsOAuthProvider) headerEnabled(OAuthSpec *Middleware) bool {
	return OAuthSpec.Spec.UpstreamAuth.OAuth.ClientCredentials.Header.Enabled
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

type ClientCredentialsClient struct {
	mw *Middleware
}

type PasswordClient struct {
	mw *Middleware
}

func generateClientCredentialsCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	key := fmt.Sprintf(
		"cc-%s|%s|%s|%s",
		apiId,
		config.ClientCredentials.ClientID,
		config.ClientCredentials.TokenURL,
		strings.Join(config.ClientCredentials.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

func retryGetKeyAndLock(cacheKey string, cache Storage) (string, error) {
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

	return "", fmt.Errorf("failed to acquire lock after retries: %w", err)
}

func SetExtraMetadata(r *http.Request, keyList []string, metadata map[string]interface{}) {
	contextDataObject := CtxGetData(r)
	if contextDataObject == nil {
		contextDataObject = make(map[string]interface{})
	}
	for _, key := range keyList {
		if val, ok := metadata[key]; ok && val != "" {
			contextDataObject[key] = val
		}
	}
	CtxSetData(r, contextDataObject)
}

// EventUpstreamOAuthMeta is the metadata structure for an upstream OAuth event
type EventUpstreamOAuthMeta struct {
	model.EventMetaDefault
	APIID string
}

func (p *PasswordOAuthProvider) getOAuthToken(r *http.Request, mw *Middleware) (string, error) {
	client := PasswordClient{mw}
	token, err := client.GetToken(r)
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

func generatePasswordOAuthCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	key := fmt.Sprintf(
		"pw-%s|%s|%s|%s",
		apiId,
		config.PasswordAuthentication.ClientID,
		config.PasswordAuthentication.ClientSecret,
		strings.Join(config.PasswordAuthentication.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

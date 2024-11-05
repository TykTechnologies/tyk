package upstreamoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/internal/crypto"
)

type Cache interface {
	// GetToken returns the token from cache or issues a request to obtain it from the OAuth provider.
	GetToken(r *http.Request) (string, error)
	// ObtainToken issues a request to obtain the token from the OAuth provider.
	ObtainToken(ctx context.Context) (*oauth2.Token, error)
}

func getToken(r *http.Request, cacheKey string, obtainTokenFunc func(context.Context) (*oauth2.Token, error), secret string, extraMetadata []string, cache Storage) (string, error) {
	tokenData, err := retryGetKeyAndLock(cacheKey, cache)
	if err != nil {
		return "", err
	}

	if tokenData != "" {
		tokenContents, err := UnmarshalTokenData(tokenData)
		if err != nil {
			return "", err
		}
		decryptedToken := crypto.Decrypt(crypto.GetPaddedString(secret), tokenContents.Token)
		SetExtraMetadata(r, extraMetadata, tokenContents.ExtraMetadata)
		return decryptedToken, nil
	}

	token, err := obtainTokenFunc(r.Context())
	if err != nil {
		return "", err
	}

	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(secret), token.AccessToken)
	tokenDataBytes, err := CreateTokenDataBytes(encryptedToken, token, extraMetadata)
	if err != nil {
		return "", err
	}
	metadataMap := BuildMetadataMap(token, extraMetadata)
	SetExtraMetadata(r, extraMetadata, metadataMap)

	ttl := time.Until(token.Expiry)
	if err := setTokenInCache(cache, cacheKey, string(tokenDataBytes), ttl); err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func setTokenInCache(cache Storage, cacheKey string, token string, ttl time.Duration) error {
	oauthTokenExpiry := time.Now().Add(ttl)
	return cache.SetKey(cacheKey, token, int64(time.Until(oauthTokenExpiry).Seconds()))
}

func CreateTokenDataBytes(encryptedToken string, token *oauth2.Token, extraMetadataKeys []string) ([]byte, error) {
	td := TokenData{
		Token:         encryptedToken,
		ExtraMetadata: BuildMetadataMap(token, extraMetadataKeys),
	}
	return json.Marshal(td)
}

func UnmarshalTokenData(tokenData string) (TokenData, error) {
	var tokenContents TokenData
	err := json.Unmarshal([]byte(tokenData), &tokenContents)
	if err != nil {
		return TokenData{}, fmt.Errorf("failed to unmarshal token data: %w", err)
	}
	return tokenContents, nil
}

func BuildMetadataMap(token *oauth2.Token, extraMetadataKeys []string) map[string]interface{} {
	metadataMap := make(map[string]interface{})
	for _, key := range extraMetadataKeys {
		if val := token.Extra(key); val != "" && val != nil {
			metadataMap[key] = val
		}
	}
	return metadataMap
}

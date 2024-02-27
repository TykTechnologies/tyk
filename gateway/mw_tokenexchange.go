package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tyk/internal/cache"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenExchangeRequest struct {
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	GrantType        string `bson:"grant_type" json:"grant_type"`
	SubjectToken     string `json:"subject_token,omitempty"`
	SubjectTokenType string `bson:"subject_token_type" json:"subject_token_type,omitempty"`
	//GrantType string `bson:"grant_type" json:"grant_type,omitempty"`
	//Audience  string `bson:"audience" json:"audience,omitempty"`

	// OPTIONAL. A URI that indicates the target service or resource where the
	//client intends to use the requested security token.
	// Format: Its value MUST be an absolute URI, as specified by Section 4.3
	// of [RFC3986].  The URI MUST NOT include a fragment component or a query component.
	//Resource string `bson:"resource" json:"resource,omitempty"`

	// OPTIONAL. A list of space-delimited, case-sensitive strings.  The strings
	Scope string `bson:"scope" json:"scope,omitempty"`

	// OPTIONAL. A security token that represents the identity of the acting party. Typically,
	// this will be the party that is authorized to use the requested security token and act on behalf of the subject.
	//ActorToken string `bson:"actor_token" json:"actor_token,omitempty"`

	// An identifier, as described in Section 3, that indicates the type of the security token
	// in the actor_token parameter. This is REQUIRED when the actor_token parameter is present
	// in the request but MUST NOT be included otherwise.
	//ActorTokenTYpe ActorTokenType `bson:"actor_token_type" json:"actor_token_type,omitempty"`
}

type TokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type TokenExchangeMW struct {
	*BaseMiddleware
	tokCache cache.Repository
}

func (k *TokenExchangeMW) Name() string {
	return "TokenExchangeMW"
}

func (k *TokenExchangeMW) EnabledForSpec() bool {
	if k.Spec.TokenExchangeOptions.Enable {
		k.tokCache = cache.New(240, 30)
		return true
	}
	return false
}

const (
	// TokenExchangeGrantType is the grant type for token exchange
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
)

func (k *TokenExchangeMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	subjectToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	sig := strings.Split(subjectToken, ".")[2]
	var newAccessToken string
	if exchangedToken, ok := k.tokCache.Get(sig); ok {
		newAccessToken = exchangedToken.(string)
	} else {
		// first time we see this token
		ter := TokenExchangeRequest{
			ClientID:     k.Spec.TokenExchangeOptions.ClientID,
			ClientSecret: k.Spec.TokenExchangeOptions.ClientSecret,
			SubjectToken: subjectToken,
			GrantType:    TokenExchangeGrantType,
		}

		params := url.Values{}
		params.Set("client_id", ter.ClientID)
		params.Set("client_secret", ter.ClientSecret)
		params.Set("subject_token", ter.SubjectToken)
		params.Set("grant_type", ter.GrantType)

		req, err := http.NewRequest(http.MethodPost, k.Spec.TokenExchangeOptions.TokenEndpoint, strings.NewReader(params.Encode()))
		if err != nil {
			return err, http.StatusInternalServerError
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		c := &http.Client{}
		res, err := c.Do(req)
		if err != nil {
			return err, http.StatusInternalServerError
		}

		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(res.Body)
			log.Error("token exchange failed: %s", string(bodyBytes))
			return fmt.Errorf("token exchange failed: %s", res.Status), http.StatusInternalServerError
		}

		tokenResponse := TokenExchangeResponse{}
		json.NewDecoder(res.Body).Decode(&tokenResponse)

		newAccessToken = tokenResponse.AccessToken
		k.tokCache.Set(sig, newAccessToken, 5)
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", newAccessToken))
	return nil, http.StatusOK
}

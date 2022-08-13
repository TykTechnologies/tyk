package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// OAuth2IntrospectionMW checks for an OAuth2 access token, and if present, will perform an introspection call to
// the pre-configured introspection endpoint. Assuming the token is active, it will replace the token with a "fake"
// JWT which has been created from the introspection response. The Gateway may then use standard JWT middleware to
// validate the claims and scopes of the access token.
type OAuth2IntrospectionMW struct {
	BaseMiddleware
	client *http.Client
}

func (k *OAuth2IntrospectionMW) Name() string {
	return "OAuth2IntrospectionMW"
}

func (k *OAuth2IntrospectionMW) EnabledForSpec() bool {
	if !k.Spec.EnableOAuth2Introspection || !k.Spec.EnableJWT {
		return false
	}

	k.client = http.DefaultClient

	if k.Spec.OAuth2IntrospectionAuth == "" || k.Spec.OAuth2IntrospectionEndpoint == "" {
		k.logger.Warning("introspection enabled, but missing configs - skipping")
		return false
	}

	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OAuth2IntrospectionMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	// Get access token from Header
	auth := r.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		return errors.New("no bearer token"), http.StatusUnauthorized
	}

	data := url.Values{}
	data.Set("token", split[1])
	data.Set("token_type_hint", "access_token")

	req, _ := http.NewRequest(http.MethodPost, k.Spec.OAuth2IntrospectionEndpoint, strings.NewReader(data.Encode()))
	req.Header.Set("Authorization", k.Spec.OAuth2IntrospectionAuth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	reqBytes, _ := httputil.DumpRequest(req, true)
	println(string(reqBytes))

	res, err := k.client.Do(req)
	if err != nil {
		return err, http.StatusInternalServerError
	}
	defer res.Body.Close()

	resBytes, _ := httputil.DumpResponse(res, true)
	k.logger.Warningf("RES: \n%s", string(resBytes))

	bodyBytes, _ := ioutil.ReadAll(res.Body)
	claims := make(jwt.MapClaims)

	json.Unmarshal(bodyBytes, &claims)

	if active, ok := claims["active"]; !ok {
		// active claim missing
		return errors.New("missing active claim"), http.StatusUnauthorized
	} else {
		if active != true {
			return errors.New("token inactive"), http.StatusUnauthorized
		}
	}

	// demo showing that we can inject claims
	claims["asoorm"] = true
	claims["pol"] = "demo"

	// demo showing that we can delete claims
	for _, claim := range k.Spec.OAuth2IntrospectionDeleteClaims {
		delete(claims, claim)
	}

	// signing the JWT
	jwtToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString([]byte("foobar"))
	if err != nil {
		return err, http.StatusUnauthorized
	}

	// injecting into the authorization header - which can be picked up by the JWT middleware
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	return nil, http.StatusOK
}

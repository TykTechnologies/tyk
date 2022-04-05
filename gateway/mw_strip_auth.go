package gateway

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
)

type StripAuth struct {
	BaseMiddleware
}

func (sa *StripAuth) Name() string {
	return "StripAuth"
}

func (sa *StripAuth) EnabledForSpec() bool {
	return sa.Spec.StripAuthData
}

func (sa *StripAuth) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	strip := func(typ string, config *apidef.AuthConfig) {
		log.WithFields(logrus.Fields{
			"prefix": sa.Name(),
		}).Debugf("%s: %+v\n", typ, config)

		if config.UseParam {
			sa.stripFromParams(r, config)
		}
		sa.stripFromHeaders(r, config)
	}

	for typ, config := range sa.Spec.AuthConfigs {
		strip(typ, &config)
	}

	// For backward compatibility
	if len(sa.Spec.AuthConfigs) == 0 {
		strip(apidef.AuthTokenType, &sa.Spec.Auth)
	}

	return nil, http.StatusOK
}

// strips auth from query string params
func (sa *StripAuth) stripFromParams(r *http.Request, config *apidef.AuthConfig) {

	reqUrlPtr, _ := url.Parse(r.URL.String())

	authParamName := "Authorization"

	if config.ParamName != "" {
		authParamName = config.ParamName
	} else if config.AuthHeaderName != "" {
		authParamName = config.AuthHeaderName
	}

	queryStringValues := reqUrlPtr.Query()

	queryStringValues.Del(authParamName)

	reqUrlPtr.RawQuery = queryStringValues.Encode()

	r.URL, _ = r.URL.Parse(reqUrlPtr.String())
}

// strips auth key from headers
func (sa *StripAuth) stripFromHeaders(r *http.Request, config *apidef.AuthConfig) {

	authHeaderName := "Authorization"
	if config.AuthHeaderName != "" {
		authHeaderName = config.AuthHeaderName
	}

	r.Header.Del(authHeaderName)

	// Strip Authorization from Cookie Header
	cookieName := authHeaderName
	if config.CookieName != "" {
		cookieName = config.CookieName
	}

	cookieValue := r.Header.Get("Cookie")

	cookies := strings.Split(cookieValue, ";")
	for i, c := range cookies {
		if strings.HasPrefix(strings.TrimSpace(c), cookieName) {
			cookies = append(cookies[:i], cookies[i+1:]...)
			cookieValue = strings.Join(cookies, ";")
			r.Header.Set("Cookie", cookieValue)
			break
		}
	}
}

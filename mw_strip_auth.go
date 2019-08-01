package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Sirupsen/logrus"
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

	config := sa.Spec.Auth

	log.WithFields(logrus.Fields{
		"prefix": sa.Name(),
	}).Debugf("sa.Spec.Auth: %+v\n", config)

	if sa.Spec.Auth.UseParam {
		sa.stripFromParams(r)
	}
	sa.stripFromHeaders(r)

	return nil, http.StatusOK
}

// strips auth from query string params
func (sa *StripAuth) stripFromParams(r *http.Request) {

	config := sa.Spec.Auth

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
func (sa *StripAuth) stripFromHeaders(r *http.Request) {

	config := sa.Spec.Auth

	authHeaderName := "Authorization"
	if config.AuthHeaderName != "" {
		authHeaderName = config.AuthHeaderName
	}

	r.Header.Del(authHeaderName)

	// Strip Authorization from Cookie Header
	cookieName := "Cookie"
	if config.CookieName != "" {
		cookieName = config.CookieName
	}

	cookieValue := r.Header.Get(cookieName)

	cookies := strings.Split(r.Header.Get(cookieName), ";")
	for i, c := range cookies {
		if strings.HasPrefix(c, authHeaderName) {
			cookies = append(cookies[:i], cookies[i+1:]...)
			cookieValue = strings.Join(cookies, ";")
			r.Header.Set(cookieName, cookieValue)
			break
		}

	}
}

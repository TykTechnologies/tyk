package openid

import (
	"fmt"
	"net/http"

	"github.com/square/go-jose"
)

type jwksGetter interface {
	getJwkSet(string) (jose.JSONWebKeySet, error)
}

type httpJwksProvider struct {
	getJwks    httpGetFunc
	decodeJwks decodeResponseFunc
}

func newHTTPJwksProvider(gf httpGetFunc, df decodeResponseFunc) *httpJwksProvider {
	return &httpJwksProvider{gf, df}
}

func (httpProv *httpJwksProvider) getJwkSet(url string) (jose.JSONWebKeySet, error) {

	var jwks jose.JSONWebKeySet
	resp, err := httpProv.getJwks(url)

	if err != nil {
		return jwks, &ValidationError{Code: ValidationErrorGetJwksFailure, Message: fmt.Sprintf("Failure while contacting the jwk endpoint %v: %v", url, err), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	defer resp.Body.Close()

	if err := httpProv.decodeJwks(resp.Body, &jwks); err != nil {
		return jwks, &ValidationError{Code: ValidationErrorDecodeJwksFailure, Message: fmt.Sprintf("Failure while decoding the jwk retrieved from the endpoint %v: %v", url, err), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	return jwks, nil
}

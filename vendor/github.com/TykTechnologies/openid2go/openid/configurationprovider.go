package openid

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const wellKnownOpenIdConfiguration = "/.well-known/openid-configuration"

type httpGetFunc func(url string) (*http.Response, error)
type decodeResponseFunc func(io.Reader, interface{}) error

type configurationGetter interface { // Getter
	getConfiguration(string) (configuration, error)
}

type httpConfigurationProvider struct { //configurationProvider
	getConfig    httpGetFunc        //httpGetter
	decodeConfig decodeResponseFunc //responseDecoder
}

func newHTTPConfigurationProvider(gc httpGetFunc, dc decodeResponseFunc) *httpConfigurationProvider {
	return &httpConfigurationProvider{gc, dc}
}

func jsonDecodeResponse(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

func (httpProv *httpConfigurationProvider) getConfiguration(issuer string) (configuration, error) {
	// Workaround for tokens issued by google
	if issuer == "accounts.google.com" {
		issuer = "https://" + issuer
	}

	configurationUri := strings.TrimSuffix(issuer, "/") + wellKnownOpenIdConfiguration
	var config configuration
	resp, err := httpProv.getConfig(configurationUri)
	if err != nil {
		return config, &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while contacting the configuration endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	defer resp.Body.Close()

	if err := httpProv.decodeConfig(resp.Body, &config); err != nil {
		return config, &ValidationError{Code: ValidationErrorDecodeOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while decoding the configuration retrived from endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	return config, nil

}

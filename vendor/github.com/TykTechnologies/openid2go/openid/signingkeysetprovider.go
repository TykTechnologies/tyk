package openid

import (
	"fmt"
	"net/http"
)

type signingKeySetGetter interface {
	getSigningKeySet(issuer string) ([]signingKey, error)
}

type signingKeySetProvider struct {
	configGetter configurationGetter
	jwksGetter   jwksGetter
	keyEncoder   pemEncodeFunc
}

type signingKey struct {
	keyID string
	key   []byte
}

func newSigningKeySetProvider(cg configurationGetter, jg jwksGetter, ke pemEncodeFunc) *signingKeySetProvider {
	return &signingKeySetProvider{cg, jg, ke}
}

func (signProv *signingKeySetProvider) getSigningKeySet(iss string) ([]signingKey, error) {
	conf, err := signProv.configGetter.getConfiguration(iss)

	if err != nil {
		return nil, err
	}

	jwks, err := signProv.jwksGetter.getJwkSet(conf.JwksUri)

	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) == 0 {
		return nil, &ValidationError{Code: ValidationErrorEmptyJwk, Message: fmt.Sprintf("The jwk set retrieved for the issuer %v does not contain any key.", iss), HTTPStatus: http.StatusUnauthorized}
	}

	sk := make([]signingKey, len(jwks.Keys))

	for i, k := range jwks.Keys {
		ek, err := signProv.keyEncoder(k.Key)
		if err != nil {
			return nil, err
		}

		sk[i] = signingKey{k.KeyID, ek}
	}

	return sk, nil
}

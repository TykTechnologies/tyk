package openid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
)

var lock = sync.RWMutex{}

type signingKeyGetter interface {
	flushCachedSigningKeys(issuer string) error
	getSigningKey(issuer string, kid string) (interface{}, error)
}

type signingKeyProvider struct {
	keySetGetter signingKeySetGetter
	jwksMap      map[string][]signingKey
}

func newSigningKeyProvider(kg signingKeySetGetter) *signingKeyProvider {
	keyMap := make(map[string][]signingKey)
	return &signingKeyProvider{kg, keyMap}
}

func (s *signingKeyProvider) flushCachedSigningKeys(issuer string) error {
	lock.Lock()
	defer lock.Unlock()
	delete(s.jwksMap, issuer)
	return nil
}

func (s *signingKeyProvider) refreshSigningKeys(issuer string) error {
	skeys, err := s.keySetGetter.getSigningKeySet(issuer)

	if err != nil {
		return err
	}

	lock.Lock()
	s.jwksMap[issuer] = skeys
	lock.Unlock()
	return nil
}

func parsePublicKey(data []byte) (interface{}, error) {
	input := data
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}
	var pub interface{}
	var err error
	pub, err = x509.ParsePKIXPublicKey(input)
	if err != nil {
		cert, err0 := x509.ParseCertificate(input)
		if err0 != nil {
			return nil, err0
		}
		pub = cert.PublicKey
		err = nil
	}
	return pub, err
}

func (s *signingKeyProvider) getSigningKey(issuer string, kid string) (interface{}, error) {
	lock.RLock()
	sk := findKey(s.jwksMap, issuer, kid)
	lock.RUnlock()

	if sk != nil {
		parsed, pErr := parsePublicKey(sk)
		if pErr != nil {
			return sk, nil
		}
		return parsed, nil
	}

	err := s.refreshSigningKeys(issuer)

	if err != nil {
		return nil, err
	}

	lock.RLock()
	sk = findKey(s.jwksMap, issuer, kid)
	lock.RUnlock()

	if sk == nil {
		return nil, &ValidationError{Code: ValidationErrorKidNotFound, Message: fmt.Sprintf("The jwk set retrieved for the issuer %v does not contain a key identifier %v.", issuer, kid), HTTPStatus: http.StatusUnauthorized}
	}

	parsed, pErr := parsePublicKey(sk)
	if pErr != nil {
		return sk, nil
	}

	return parsed, nil
}

func findKey(km map[string][]signingKey, issuer string, kid string) []byte {

	if skSet, ok := km[issuer]; ok {
		if kid == "" {
			return skSet[0].key
		} else {
			for _, sk := range skSet {
				if sk.keyID == kid {
					return sk.key
				}
			}
		}
	}

	return nil
}

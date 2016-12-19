package openid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

type pemEncodeFunc func(key interface{}) ([]byte, error)

func pemEncodePublicKey(key interface{}) ([]byte, error) {
	mk, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, &ValidationError{Code: ValidationErrorMarshallingKey, Message: fmt.Sprint("The jwk key could not be marshalled."), HTTPStatus: http.StatusInternalServerError, Err: err}
	}

	ed := pem.EncodeToMemory(&pem.Block{
		Bytes: mk,
	})

	return ed, nil
}

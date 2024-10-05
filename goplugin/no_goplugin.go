//go:build !cgo
// +build !cgo

package goplugin

import (
	"fmt"
	"net/http"
)

const (
	errNotImplemented = "goplugin.%s is disabled, build gateway with CGO_ENABLED=1"
)

func GetSymbol(modulePath string, symbol string) (interface{}, error) {
	return nil, fmt.Errorf(errNotImplemented, "GetSymbol")
}

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	return nil, fmt.Errorf(errNotImplemented, "GetHandler")
}

func GetResponseHandler(path string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request), error) {
	return nil, fmt.Errorf(errNotImplemented, "GetResponseHandler")
}

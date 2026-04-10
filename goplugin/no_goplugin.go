//go:build !goplugin
// +build !goplugin

package goplugin

import (
	"fmt"
	"net/http"
)

const (
	errNotImplemented = "goplugin.%s is disabled, use -tags=goplugin to enable"
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

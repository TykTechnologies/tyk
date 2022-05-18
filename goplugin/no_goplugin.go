//go:build !goplugin
// +build !goplugin

package goplugin

import (
	"fmt"
	"net/http"
)

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	return nil, fmt.Errorf("goplugin.GetHandler is disabled, please disable build flag 'nogoplugin'")
}

func GetResponseHandler(path string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request), error) {
	return nil, fmt.Errorf("goplugin.GetResponseHandler is disabled, please disable build flag 'nogoplugin'")
}

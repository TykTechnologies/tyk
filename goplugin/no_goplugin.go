// +build !goplugin

package goplugin

import (
	"fmt"
	"net/http"
)

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	return nil, fmt.Errorf("goplugin.GetHandler is disabled, please disable build flag 'nogoplugin'")
}

func GetResponseHandler(path string, symbol string) (func(w http.ResponseWriter, r *http.Request, res *http.Response), error) {
	return nil, nil
}
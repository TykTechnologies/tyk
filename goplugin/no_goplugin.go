// +build !goplugin

package goplugin

import (
	"fmt"
	"github.com/TykTechnologies/tyk/user"
	"net/http"
)

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	return nil, fmt.Errorf("goplugin.GetHandler is disabled, please disable build flag 'nogoplugin'")
}

func GetResponseHandler(path string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState), error) {
	return nil, fmt.Errorf("goplugin.GetResponseHandler is disabled, please disable build flag 'nogoplugin'")
}

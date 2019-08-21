// +build !goplugin

package goplugin

import (
	"fmt"
	"net/http"
)

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	return nil, fmt.Errorf("goplugin.GetHandler is disabled, please disable build flag 'nogoplugin'")
}

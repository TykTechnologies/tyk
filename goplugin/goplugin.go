//go:build cgo
// +build cgo

package goplugin

import (
	"errors"
	"net/http"
	"plugin"
)

func GetSymbol(modulePath string, symbol string) (interface{}, error) {
	// try to load plugin
	loadedPlugin, err := plugin.Open(modulePath)
	if err != nil {
		return nil, err
	}

	// try to lookup function symbol
	funcSymbol, err := loadedPlugin.Lookup(symbol)
	if err != nil {
		return nil, err
	}

	return funcSymbol, nil
}

func GetHandler(modulePath string, symbol string) (http.HandlerFunc, error) {
	funcSymbol, err := GetSymbol(modulePath, symbol)
	if err != nil {
		return nil, err
	}

	// try to cast symbol to real func
	pluginHandler, ok := funcSymbol.(func(http.ResponseWriter, *http.Request))
	if !ok {
		return nil, errors.New("could not cast function symbol to http.HandlerFunc")
	}

	return pluginHandler, nil
}

func GetResponseHandler(modulePath string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request), error) {
	funcSymbol, err := GetSymbol(modulePath, symbol)
	if err != nil {
		return nil, err
	}

	// try to cast symbol to real func
	respPluginHandler, ok := funcSymbol.(func(rw http.ResponseWriter, res *http.Response, req *http.Request))
	if !ok {
		return nil, errors.New("could not cast function symbol to TykResponseHandler")
	}

	return respPluginHandler, nil
}

//go:build goplugin
// +build goplugin

package goplugin

import (
	"errors"
	"net/http"
	"plugin"
)

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	// try to load plugin
	loadedPlugin, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	// try to lookup function symbol
	funcSymbol, err := loadedPlugin.Lookup(symbol)
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

func GetResponseHandler(path string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request), error) {
	// try to load plugin
	loadedPlugin, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	// try to lookup function symbol
	funcSymbol, err := loadedPlugin.Lookup(symbol)
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

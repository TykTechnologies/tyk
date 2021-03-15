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

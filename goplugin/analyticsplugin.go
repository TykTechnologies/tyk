// +build goplugin

package goplugin

import (
	"errors"
	"github.com/TykTechnologies/tyk/analytics"
	"plugin"
)

func GetAnalyticsHandler(path string, symbol string) (func(record *analytics.Record), error) {
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
	pluginHandler, ok := funcSymbol.(func(record *analytics.Record))
	if !ok {
		return nil, errors.New("could not cast function symbol to AnalyticsPlugin function")
	}

	return pluginHandler, nil
}

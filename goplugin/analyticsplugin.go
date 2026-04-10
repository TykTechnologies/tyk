//go:build goplugin
// +build goplugin

package goplugin

import (
	"errors"
	"plugin"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func GetAnalyticsHandler(path string, symbol string) (func(record *analytics.AnalyticsRecord), error) {
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
	pluginHandler, ok := funcSymbol.(func(record *analytics.AnalyticsRecord))
	if !ok {
		return nil, errors.New("could not cast function symbol to AnalyticsPlugin function")
	}

	return pluginHandler, nil
}

package goplugin

import (
	"net/http"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/plugin"
)

// GetSymbol only tests plugin loading. Used in tyk plugin cli.
// Don't encourage internal use.
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
	loadedPlugin, err := plugin.Open(modulePath)
	if err != nil {
		return nil, err
	}

	var handler func(http.ResponseWriter, *http.Request)

	if err := loadedPlugin.As(&handler, symbol); err != nil {
		return nil, errors.Wrap(err, "could not cast function symbol to AnalyticsPlugin function")
	}
	return handler, nil
}

func GetResponseHandler(modulePath string, symbol string) (func(rw http.ResponseWriter, res *http.Response, req *http.Request), error) {
	loadedPlugin, err := plugin.Open(modulePath)
	if err != nil {
		return nil, err
	}

	var handler func(rw http.ResponseWriter, res *http.Response, req *http.Request)

	if err := loadedPlugin.As(&handler, symbol); err != nil {
		return nil, errors.Wrap(err, "could not cast function symbol to AnalyticsPlugin function")
	}
	return handler, nil
}

func GetAnalyticsHandler(name string, symbol string) (func(record *analytics.AnalyticsRecord), error) {
	// try to load plugin
	loadedPlugin, err := plugin.Open(name)
	if err != nil {
		return nil, err
	}

	var handler func(record *analytics.AnalyticsRecord)

	if err := loadedPlugin.As(&handler, symbol); err != nil {
		return nil, errors.Wrap(err, "could not cast function symbol to AnalyticsPlugin function")
	}
	return handler, nil
}

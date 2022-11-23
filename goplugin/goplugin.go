//go:build goplugin
// +build goplugin

package goplugin

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"plugin"

	"github.com/Binject/universal"
)

// pluginOpen loads a .so plugin. It is a wrapper around plugin.Open,
// and adds additional checks if the plugin can be loaded.
func pluginOpen(name string) (*plugin.Plugin, error) {
	// read plugin file to load from memory
	pluginBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading plugin: %w", err)
	}

	// try to load plugin to userspace as a pre-flight check
	if err := pluginPreload(name, pluginBytes); err != nil {
		return nil, fmt.Errorf("error preloading plugin: %w", err)
	}

	// try to load plugin
	plugin, err := plugin.Open(name)
	if err != nil {
		return nil, fmt.Errorf("error loading plugin: %w", err)
	}

	return plugin, nil
}

// pluginPreload loads the bytes of .so libraries in userspace
// and returns an error if something failed.
//
// This function is a work-around for a non-recoverable panic
// in the stdlib: https://github.com/golang/go/issues/33072
//
// The work-around relies on binject/universal, which can
// load plugin symbols from userspace, under the asumption
// that it triggers a recoverable panic in the worst case,
// and that it matches dlopen behaviour of the stdlib.
func pluginPreload(name string, pluginBytes []byte) error {
	loader, err := universal.NewLoader()
	if err != nil {
		return err
	}

	_, err = loader.LoadLibrary(name, &pluginBytes)
	return err
}

func GetHandler(path string, symbol string) (http.HandlerFunc, error) {
	// try to load plugin
	loadedPlugin, err := pluginOpen(path)
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
	loadedPlugin, err := pluginOpen(path)
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

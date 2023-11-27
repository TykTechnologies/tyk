// The native package provides a plugin subsystem that extends the
// behaviour of the standard library `plugin` package.
//
// The behaviour is extended with a Symbols() that allows listing
// the plugin symbols declared and their function signatures.

package native

import (
	"fmt"
	"plugin"
	"strings"

	"github.com/TykTechnologies/tyk/plugins/model"
)

// Plugin is the utility object that wraps plugin.Plugin.
type Plugin struct {
	name   string
	plugin *plugin.Plugin
}

// Assert that plugin implements model.Plugin interfaces.
var _ model.Plugin = &Plugin{}

// NewPlugin will attempt to open the plugin with plugin.Open and provide
// an internal representation of the plugin. It implements a compatible API
// signature to the internal plugin package.
func NewPlugin(name string) (*Plugin, error) {
	p, err := plugin.Open(name)
	if err != nil {
		return nil, fmt.Errorf("Error loading native plugin %s: %w", name, err)
	}

	result := &Plugin{
		name:   name,
		plugin: p,
	}

	return result, nil
}

// Lookup returns the plugin symbol value from the loaded plugin.
func (p *Plugin) Lookup(name string) (plugin.Symbol, error) {
	return p.plugin.Lookup(name)
}

// Symbols will traverse the internal representation of plugin.Plugin and use
// the reflection features inside fmt.Sprintf (`%+v` and `%T`). This isn't likely
// to work in restricted environments where reflection is not available. Note that
// particularly reflection is disabled in google app engine sandbox environments.
func (p *Plugin) Symbols() (map[string]string, error) {
	internals := fmt.Sprintf("%+v", p.plugin)

	// extract syms map from stdlib internal symbols table
	parts := strings.SplitN(internals, "syms:map[", 2)
	if len(parts) < 2 {
		return nil, model.ErrNoSymbols
	}

	// split on map closure
	parts = strings.SplitN(parts[1], "]", 2)

	// get symbols list
	symbols := strings.Fields(parts[0])
	result := make(map[string]string, len(symbols))
	for _, sym := range symbols {
		symAddr := strings.Split(sym, ":")
		name := symAddr[0]

		symbol, err := p.plugin.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("Error looking up symbol: %w", err)
		}

		result[name] = fmt.Sprintf("%T", symbol)
	}

	return result, nil
}

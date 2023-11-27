// The registry package provides a plugin subsystem that matches the
// native plugins. You can register plugin symbols and interchange the
// instance of registry.Plugin with native.Plugin.
package registry

import (
	"fmt"
	"plugin"

	"github.com/TykTechnologies/tyk/plugins/model"
)

// Plugin implements model.Plugin.
type Plugin struct {
	name string

	syms map[string]plugin.Symbol
}

// Assert that plugin implements model.Plugin and model.Registry interfaces.
var _ model.Plugin = &Plugin{}
var _ model.Registry = &Plugin{}

// NewPlugin will create a plugin registry object. After creating it, plugins
// may be registered by invoking Register(). Any registered plugin will be
// returned by the Lookup and Symbols methods.
func NewPlugin(name string) (*Plugin, error) {
	return &Plugin{
		name: name,
		syms: make(map[string]plugin.Symbol),
	}, nil
}

// Register creates a plugin symbol to be returned by Lookup.
func (p *Plugin) Register(name string, val plugin.Symbol) {
	p.syms[name] = val
}

// Lookup returns the plugin symbol value from the loaded plugin.
func (p *Plugin) Lookup(name string) (plugin.Symbol, error) {
	if sym, ok := p.syms[name]; ok {
		return sym, nil
	}

	return nil, model.ErrNotFound
}

// Symbols returns an internal map of symbols and it's type representations.
func (p *Plugin) Symbols() (map[string]string, error) {
	if len(p.syms) == 0 {
		return nil, nil
	}

	result := make(map[string]string, len(p.syms))

	for k, v := range p.syms {
		result[k] = fmt.Sprintf("%T", v)
	}

	return result, nil
}

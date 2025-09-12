package gateway

import (
	"sort"

	"github.com/justinas/alice"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

// GlobalMiddlewareFactory creates a global middleware instance
type GlobalMiddlewareFactory func(*GlobalBaseMiddleware, map[string]interface{}) TykMiddleware

// GlobalMiddlewareRegistry manages global middleware plugins
type GlobalMiddlewareRegistry struct {
	factories map[string]GlobalMiddlewareFactory
}

// NewGlobalMiddlewareRegistry creates a new global middleware registry
func NewGlobalMiddlewareRegistry() *GlobalMiddlewareRegistry {
	return &GlobalMiddlewareRegistry{
		factories: make(map[string]GlobalMiddlewareFactory),
	}
}

// Register registers a global middleware factory
func (r *GlobalMiddlewareRegistry) Register(name string, factory GlobalMiddlewareFactory) {
	r.factories[name] = factory
}

// Create creates a global middleware instance
func (r *GlobalMiddlewareRegistry) Create(name string, base *GlobalBaseMiddleware, config map[string]interface{}) TykMiddleware {
	factory, exists := r.factories[name]
	if !exists {
		return nil
	}
	return factory(base, config)
}

// HasMiddleware checks if a middleware is registered
func (r *GlobalMiddlewareRegistry) HasMiddleware(name string) bool {
	_, exists := r.factories[name]
	return exists
}

// GetRegisteredMiddlewares returns list of registered middleware names
func (r *GlobalMiddlewareRegistry) GetRegisteredMiddlewares() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// initGlobalMiddlewareRegistry initializes the global middleware registry with built-in middleware
func (gw *Gateway) initGlobalMiddlewareRegistry() {
	gw.GlobalMiddlewareRegistry = NewGlobalMiddlewareRegistry()
	
	// Register built-in global middleware
	gw.GlobalMiddlewareRegistry.Register("traffic_mirror", func(base *GlobalBaseMiddleware, config map[string]interface{}) TykMiddleware {
		return &GlobalTrafficMirrorMiddleware{
			GlobalBaseMiddleware: base,
			configData:           config,
		}
	})
	
	gw.GlobalMiddlewareRegistry.Register("global_headers", func(base *GlobalBaseMiddleware, config map[string]interface{}) TykMiddleware {
		return &GlobalHeadersMiddleware{
			GlobalBaseMiddleware: base,
			configData:           config,
		}
	})
}

// shouldSkipForAPI checks if global middleware should be skipped for a specific API
func (gw *Gateway) shouldSkipForAPI(plugin config.GlobalPluginConfig, apiID string) bool {
	// Check exclude list
	for _, excludeID := range plugin.ExcludeAPIs {
		if excludeID == apiID {
			return true
		}
	}
	
	// Check include list (if specified, API must be in list)
	if len(plugin.IncludeAPIs) > 0 {
		found := false
		for _, includeID := range plugin.IncludeAPIs {
			if includeID == apiID {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	
	return false
}

// sortGlobalPlugins sorts global plugins by priority (lower numbers first)
func sortGlobalPlugins(plugins []config.GlobalPluginConfig) {
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Priority < plugins[j].Priority
	})
}

// appendGlobalMiddleware adds global middleware to the middleware chain
func (gw *Gateway) appendGlobalMiddleware(chain *[]alice.Constructor, baseMid *BaseMiddleware, phase string, apiID string) {
	globalConfig := gw.GetConfig().GlobalMiddleware
	var plugins []config.GlobalPluginConfig
	
	if phase == "pre" {
		plugins = make([]config.GlobalPluginConfig, len(globalConfig.Pre))
		copy(plugins, globalConfig.Pre)
	} else {
		plugins = make([]config.GlobalPluginConfig, len(globalConfig.Post))
		copy(plugins, globalConfig.Post)
	}
	
	// Sort by priority
	sortGlobalPlugins(plugins)
	
	for _, plugin := range plugins {
		if !plugin.Enabled {
			continue
		}
		
		// Check if this plugin should be skipped for this API
		if gw.shouldSkipForAPI(plugin, apiID) {
			continue
		}
		
		// Create global middleware instance
		globalBase := &GlobalBaseMiddleware{
			BaseMiddleware: baseMid,
			GlobalConfig:   plugin.Config,
			Phase:         phase,
			PluginName:    plugin.Name,
		}
		
		mw := gw.GlobalMiddlewareRegistry.Create(plugin.Name, globalBase, plugin.Config)
		if mw != nil {
			gw.mwAppendEnabled(chain, mw)
		} else {
			logrus.WithField("middleware", plugin.Name).Warning("Global middleware not found in registry")
		}
	}
}
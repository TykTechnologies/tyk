package gateway

import (
	"sync"

	"github.com/sirupsen/logrus"
)

// GlobalBaseMiddleware extends BaseMiddleware for global middleware functionality
type GlobalBaseMiddleware struct {
	*BaseMiddleware
	// Global configuration for this middleware instance
	GlobalConfig map[string]interface{}
	// Phase indicates when this middleware runs ("pre" or "post")
	Phase string
	// PluginName is the name of the global plugin
	PluginName string
	
	// Logger for global middleware
	globalLogger *logrus.Entry
	loggerMu     sync.Mutex
}

// NewGlobalBaseMiddleware creates a new GlobalBaseMiddleware
func NewGlobalBaseMiddleware(base *BaseMiddleware, globalConfig map[string]interface{}, phase, pluginName string) *GlobalBaseMiddleware {
	return &GlobalBaseMiddleware{
		BaseMiddleware: base,
		GlobalConfig:   globalConfig,
		Phase:         phase,
		PluginName:    pluginName,
	}
}

// Logger returns a logger specific to this global middleware instance
func (g *GlobalBaseMiddleware) Logger() *logrus.Entry {
	g.loggerMu.Lock()
	defer g.loggerMu.Unlock()
	
	if g.globalLogger == nil {
		baseLogger := g.BaseMiddleware.Logger()
		g.globalLogger = baseLogger.WithFields(logrus.Fields{
			"global_middleware": g.PluginName,
			"phase":            g.Phase,
		})
	}
	return g.globalLogger
}

// GetGlobalConfig returns the global configuration for this middleware
func (g *GlobalBaseMiddleware) GetGlobalConfig() map[string]interface{} {
	return g.GlobalConfig
}

// GetConfigValue retrieves a value from the global configuration
func (g *GlobalBaseMiddleware) GetConfigValue(key string) (interface{}, bool) {
	value, exists := g.GlobalConfig[key]
	return value, exists
}

// GetConfigString retrieves a string value from the global configuration
func (g *GlobalBaseMiddleware) GetConfigString(key string) string {
	if value, exists := g.GlobalConfig[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetConfigBool retrieves a boolean value from the global configuration
func (g *GlobalBaseMiddleware) GetConfigBool(key string) bool {
	if value, exists := g.GlobalConfig[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// GetConfigInt retrieves an integer value from the global configuration
func (g *GlobalBaseMiddleware) GetConfigInt(key string) int {
	if value, exists := g.GlobalConfig[key]; exists {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return 0
}

// GetConfigFloat retrieves a float value from the global configuration
func (g *GlobalBaseMiddleware) GetConfigFloat(key string) float64 {
	if value, exists := g.GlobalConfig[key]; exists {
		switch v := value.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return 0.0
}

// GetConfigStringSlice retrieves a string slice from the global configuration
func (g *GlobalBaseMiddleware) GetConfigStringSlice(key string) []string {
	if value, exists := g.GlobalConfig[key]; exists {
		if slice, ok := value.([]interface{}); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
		if slice, ok := value.([]string); ok {
			return slice
		}
	}
	return []string{}
}

// GetConfigMap retrieves a map from the global configuration
func (g *GlobalBaseMiddleware) GetConfigMap(key string) map[string]interface{} {
	if value, exists := g.GlobalConfig[key]; exists {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return make(map[string]interface{})
}

// IsPrePhase returns true if this is a pre-request middleware
func (g *GlobalBaseMiddleware) IsPrePhase() bool {
	return g.Phase == "pre"
}

// IsPostPhase returns true if this is a post-request middleware
func (g *GlobalBaseMiddleware) IsPostPhase() bool {
	return g.Phase == "post"
}
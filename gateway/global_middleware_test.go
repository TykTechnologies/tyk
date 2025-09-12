package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestGlobalMiddlewareRegistry(t *testing.T) {
	// Create registry
	registry := NewGlobalMiddlewareRegistry()

	// Register test middleware
	registry.Register("test_middleware", func(base *GlobalBaseMiddleware, config map[string]interface{}) TykMiddleware {
		return &TestGlobalMiddleware{
			GlobalBaseMiddleware: base,
			configData:           config,
		}
	})

	// Test middleware registration
	if !registry.HasMiddleware("test_middleware") {
		t.Error("Middleware should be registered")
	}

	if registry.HasMiddleware("nonexistent") {
		t.Error("Nonexistent middleware should not be registered")
	}

	// Test middleware creation
	base := &GlobalBaseMiddleware{}
	config := map[string]interface{}{"test": "value"}
	
	mw := registry.Create("test_middleware", base, config)
	if mw == nil {
		t.Error("Middleware should be created")
	}

	testMw, ok := mw.(*TestGlobalMiddleware)
	if !ok {
		t.Error("Middleware should be of correct type")
	}

	if testMw.configData["test"] != "value" {
		t.Error("Config should be passed correctly")
	}

	// Test nonexistent middleware creation
	nonexistentMw := registry.Create("nonexistent", base, config)
	if nonexistentMw != nil {
		t.Error("Nonexistent middleware should return nil")
	}
}

func TestGlobalMiddlewareConfigHelpers(t *testing.T) {
	config := map[string]interface{}{
		"string_val":  "test_string",
		"bool_val":    true,
		"int_val":     42,
		"float_val":   3.14,
		"slice_val":   []interface{}{"a", "b", "c"},
		"map_val":     map[string]interface{}{"key": "value"},
	}

	base := &GlobalBaseMiddleware{
		GlobalConfig: config,
	}

	// Test GetConfigString
	if base.GetConfigString("string_val") != "test_string" {
		t.Error("String value should be retrieved correctly")
	}
	if base.GetConfigString("nonexistent") != "" {
		t.Error("Nonexistent string should return empty string")
	}

	// Test GetConfigBool
	if !base.GetConfigBool("bool_val") {
		t.Error("Bool value should be retrieved correctly")
	}
	if base.GetConfigBool("nonexistent") {
		t.Error("Nonexistent bool should return false")
	}

	// Test GetConfigInt
	if base.GetConfigInt("int_val") != 42 {
		t.Error("Int value should be retrieved correctly")
	}
	if base.GetConfigInt("nonexistent") != 0 {
		t.Error("Nonexistent int should return 0")
	}

	// Test GetConfigFloat
	if base.GetConfigFloat("float_val") != 3.14 {
		t.Error("Float value should be retrieved correctly")
	}
	if base.GetConfigFloat("nonexistent") != 0.0 {
		t.Error("Nonexistent float should return 0.0")
	}

	// Test GetConfigStringSlice
	slice := base.GetConfigStringSlice("slice_val")
	if len(slice) != 3 || slice[0] != "a" || slice[1] != "b" || slice[2] != "c" {
		t.Error("String slice should be retrieved correctly")
	}
	if len(base.GetConfigStringSlice("nonexistent")) != 0 {
		t.Error("Nonexistent string slice should return empty slice")
	}

	// Test GetConfigMap
	m := base.GetConfigMap("map_val")
	if m["key"] != "value" {
		t.Error("Map should be retrieved correctly")
	}
	if len(base.GetConfigMap("nonexistent")) != 0 {
		t.Error("Nonexistent map should return empty map")
	}
}

func TestShouldSkipForAPI(t *testing.T) {
	gw := &Gateway{}

	// Test exclude list
	plugin := config.GlobalPluginConfig{
		ExcludeAPIs: []string{"api1", "api2"},
	}

	if !gw.shouldSkipForAPI(plugin, "api1") {
		t.Error("API in exclude list should be skipped")
	}

	if gw.shouldSkipForAPI(plugin, "api3") {
		t.Error("API not in exclude list should not be skipped")
	}

	// Test include list
	plugin = config.GlobalPluginConfig{
		IncludeAPIs: []string{"api1", "api2"},
	}

	if gw.shouldSkipForAPI(plugin, "api1") {
		t.Error("API in include list should not be skipped")
	}

	if !gw.shouldSkipForAPI(plugin, "api3") {
		t.Error("API not in include list should be skipped")
	}

	// Test both include and exclude
	plugin = config.GlobalPluginConfig{
		IncludeAPIs: []string{"api1", "api2"},
		ExcludeAPIs: []string{"api1"},
	}

	if !gw.shouldSkipForAPI(plugin, "api1") {
		t.Error("API in both lists should be skipped (exclude takes precedence)")
	}
}

func TestSortGlobalPlugins(t *testing.T) {
	plugins := []config.GlobalPluginConfig{
		{Priority: 3},
		{Priority: 1},
		{Priority: 2},
	}

	sortGlobalPlugins(plugins)

	if plugins[0].Priority != 1 || plugins[1].Priority != 2 || plugins[2].Priority != 3 {
		t.Error("Plugins should be sorted by priority")
	}
}

// TestGlobalMiddleware is a test middleware for testing
type TestGlobalMiddleware struct {
	*GlobalBaseMiddleware
	configData map[string]interface{}
}

func (t *TestGlobalMiddleware) Name() string {
	return "TestGlobalMiddleware"
}

func (t *TestGlobalMiddleware) EnabledForSpec() bool {
	return true
}

// Base returns the base middleware
func (t *TestGlobalMiddleware) Base() *BaseMiddleware {
	return t.GlobalBaseMiddleware.BaseMiddleware
}

// GetSpec returns the API spec
func (t *TestGlobalMiddleware) GetSpec() *APISpec {
	return t.GlobalBaseMiddleware.BaseMiddleware.Spec
}

// Config returns the middleware configuration
func (t *TestGlobalMiddleware) Config() (interface{}, error) {
	return t.configData, nil
}

func (t *TestGlobalMiddleware) Init() {}

func (t *TestGlobalMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Add test header
	r.Header.Set("X-Test-Global", "true")
	return nil, http.StatusOK
}
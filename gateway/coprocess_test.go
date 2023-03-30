package gateway

import (
	"context"
	"testing"

	"github.com/TykTechnologies/tyk/config"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func Test_getIDExtractor(t *testing.T) {
	testCases := []struct {
		name        string
		spec        *APISpec
		idExtractor IdExtractor
	}{
		{
			name: "coprocess auth disabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{},
			},
			idExtractor: nil,
		},
		{
			name: "id extractor disabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    true,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
						},
					},
				},
			},
			idExtractor: nil,
		},
		{
			name: "invalid id extractor",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    false,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
							Extractor:   struct{}{},
						},
					},
				},
			},
			idExtractor: nil,
		},
		{
			name: "valid id extractor",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						AuthCheck: apidef.MiddlewareDefinition{
							Name: "func name",
							Path: "path",
						},
						IdExtractor: apidef.MiddlewareIdExtractor{
							Disabled:    false,
							ExtractWith: apidef.ValueExtractor,
							ExtractFrom: apidef.HeaderSource,
							Extractor:   &ValueExtractor{},
						},
					},
				},
			},
			idExtractor: &ValueExtractor{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.idExtractor, getIDExtractor(tc.spec))
		})
	}
}

func Test_shouldAddConfigData(t *testing.T) {
	testCases := []struct {
		name      string
		spec      *APISpec
		shouldAdd bool
	}{
		{
			name: "disabled from config",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
				},
			},
			shouldAdd: false,
		},
		{
			name: "enabled from config - empty config data",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
					ConfigData:         map[string]interface{}{},
				},
			},
			shouldAdd: false,
		},
		{
			name: "enabled from config - non-empty config data",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ConfigDataDisabled: true,
					ConfigData: map[string]interface{}{
						"key": "value",
					},
				},
			},
			shouldAdd: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.shouldAdd, shouldAddConfigData(tc.spec))
		})
	}
}

func TestCoProcessMiddleware_EnabledForSpec(t *testing.T) {
	cfg := config.Config{}
	cfg.DisableAPILoadOnPluginError = false
	gw := NewGateway(cfg, context.Background())
	cm := CoProcessMiddleware{BaseMiddleware: BaseMiddleware{chainDef: &ChainObject{}, Gw: gw}}
	cm.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}
	assert.False(t, cm.EnabledForSpec())
	assert.False(t, cm.chainDef.Skip)

	cm.chainDef.Skip = false
	cfg.DisableAPILoadOnPluginError = true
	gw.SetConfig(cfg)
	assert.False(t, cm.EnabledForSpec())
	assert.True(t, cm.chainDef.Skip)

	cm.chainDef.Skip = false
	cfg.CoProcessOptions.EnableCoProcess = true
	gw.SetConfig(cfg)
	assert.False(t, cm.EnabledForSpec())
	assert.True(t, cm.chainDef.Skip)

	cm.chainDef.Skip = false
	cm.Spec.CustomMiddleware.Driver = apidef.PythonDriver
	loadedDrivers[apidef.PythonDriver] = nil
	assert.False(t, cm.EnabledForSpec())
	assert.True(t, cm.chainDef.Skip)

	// Success
	cm.chainDef.Skip = false
	loadedDrivers[apidef.PythonDriver] = &PythonDispatcher{}
	assert.True(t, cm.EnabledForSpec())
	assert.False(t, cm.chainDef.Skip)
}

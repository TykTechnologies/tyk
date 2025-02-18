package gateway

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/coprocess"

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

func TestSyncHeadersAndMultiValueHeaders(t *testing.T) {
	// defining the test cases
	testCases := []struct {
		name                      string
		headers                   map[string]string
		initialMultiValueHeaders  []*coprocess.Header
		expectedMultiValueHeaders []*coprocess.Header
	}{
		{
			name: "adding a header",
			headers: map[string]string{
				"Header1": "value1",
				"Header2": "value2",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"value1"},
				},
				{
					Key:    "Header2",
					Values: []string{"value2"},
				},
			},
		},
		{
			name: "removing a header",
			headers: map[string]string{
				"Header1": "value1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
				{
					Key:    "Header2",
					Values: []string{"oldValue2"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"value1"},
				},
			},
		},
		{
			name: "updating a header",
			headers: map[string]string{
				"Header1": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"oldValue1"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header1",
					Values: []string{"newValue1"},
				},
			},
		},
		{
			name: "keeping multivalue headers",
			headers: map[string]string{
				"Header": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header",
					Values: []string{"oldValue1", "value2"},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key:    "Header",
					Values: []string{"newValue1", "value2"},
				},
			},
		},
		{
			name: "empty multi value headers",
			headers: map[string]string{
				"Header": "newValue1",
			},
			initialMultiValueHeaders: []*coprocess.Header{},
			expectedMultiValueHeaders: []*coprocess.Header{
				{Key: "Header", Values: []string{"newValue1"}},
			},
		},
		{
			name: "multiple Set-Cookie headers",
			headers: map[string]string{
				"Set-Cookie": "session=abc123; Path=/",
			},
			initialMultiValueHeaders: []*coprocess.Header{
				{
					Key: "Set-Cookie",
					Values: []string{
						"session=dce123; Path=/",
						"user=john; Path=/",
						"theme=dark; Path=/",
					},
				},
			},
			expectedMultiValueHeaders: []*coprocess.Header{
				{
					Key: "Set-Cookie",
					Values: []string{
						"session=abc123; Path=/",
						"user=john; Path=/",
						"theme=dark; Path=/",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updatedMultiValueHeaders := syncHeadersAndMultiValueHeaders(tc.headers, tc.initialMultiValueHeaders)
			if !equalHeaders(updatedMultiValueHeaders, tc.expectedMultiValueHeaders) {
				t.Errorf("syncHeadersAndMultiValueHeaders() = %v, want %v", updatedMultiValueHeaders, tc.expectedMultiValueHeaders)
			}
		})
	}
}

func equalHeaders(h1, h2 []*coprocess.Header) bool {
	if len(h1) != len(h2) {
		return false
	}
	m := make(map[string][]string)
	for _, h := range h1 {
		m[h.Key] = h.Values
	}
	for _, h := range h2 {
		if !reflect.DeepEqual(m[h.Key], h.Values) {
			return false
		}
		delete(m, h.Key)
	}
	return len(m) == 0
}

func TestCoProcessMiddlewareName(t *testing.T) {
	m := &CoProcessMiddleware{}

	require.Equal(t, "CoProcessMiddleware", m.Name(), "Name method did not return the expected value")
}

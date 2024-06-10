package gateway

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
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
	// Initialize the CoProcessMiddleware
	m := &CoProcessMiddleware{BaseMiddleware: &BaseMiddleware{}}

	// Get the name using the method
	name := m.Name()

	// Check that the returned name is "CoProcessMiddleware"
	assert.Equal(t, "CoProcessMiddleware", name, "Name method did not return the expected value")
}

func TestCustomMiddlewareResponseHook_scanConfig(t *testing.T) {
	hook := &CustomMiddlewareResponseHook{}

	testCases := []struct {
		name    string
		input   any
		want    *apidef.MiddlewareDefinition
		wantErr bool
	}{
		{
			name: "Valid input",
			input: map[string]any{
				"name":          "middleware1",
				"raw_body_only": true,
			},
			want: &apidef.MiddlewareDefinition{
				Name:        "middleware1",
				RawBodyOnly: true,
			},
			wantErr: false,
		},
		{
			name:    "Marshalling error",
			input:   t.Log, // t.Log is a function, which will cause marshalling error
			want:    nil,
			wantErr: true,
		},
		{
			name: "Decoding error",
			input: map[string]any{
				"name": 123, // Invalid type for name, should be a string
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := hook.scanConfig(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.want, result)
		})
	}
}

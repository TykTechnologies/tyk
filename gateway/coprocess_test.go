package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	b3prop "go.opentelemetry.io/contrib/propagators/b3"
	gotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/coprocess"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
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

func TestValidateDriver(t *testing.T) {
	testSupportedDrivers := []apidef.MiddlewareDriver{apidef.PythonDriver, apidef.LuaDriver, apidef.GrpcDriver}
	testLoadedDrivers := map[apidef.MiddlewareDriver]coprocess.Dispatcher{apidef.GrpcDriver: &GRPCDispatcher{}}

	tests := []struct {
		name           string
		driver         apidef.MiddlewareDriver
		expectedStatus int
		expectedErr    error
	}{
		{
			name:           "Valid driver - supported and loaded",
			driver:         apidef.GrpcDriver,
			expectedStatus: http.StatusOK,
			expectedErr:    nil,
		},
		{
			name:           "Invalid driver - not supported",
			driver:         "unsupportedDriver",
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    errors.New(http.StatusText(http.StatusInternalServerError)),
		},
		{
			name:           "Invalid driver - supported but not loaded",
			driver:         apidef.PythonDriver,
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    errors.New(http.StatusText(http.StatusInternalServerError)),
		},
	}

	originalSupportedDrivers := supportedDrivers
	originalLoadedDrivers := loadedDrivers

	supportedDrivers = testSupportedDrivers
	loadedDrivers = testLoadedDrivers

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &CoProcessMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition: &apidef.APIDefinition{
							CustomMiddleware: apidef.MiddlewareSection{
								Driver: tt.driver,
							},
						},
					},
				},
			}

			status, err := mw.validateDriver()

			assert.Equal(t, tt.expectedStatus, status)
			if tt.expectedErr == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
			}
		})
	}

	supportedDrivers = originalSupportedDrivers
	loadedDrivers = originalLoadedDrivers
}

func newMinimalCoProcessor() *CoProcessor {
	gw := &Gateway{}
	gw.SetConfig(config.Config{})
	return &CoProcessor{
		Middleware: &CoProcessMiddleware{
			BaseMiddleware: &BaseMiddleware{
				Gw: gw,
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{},
				},
			},
			HookType: coprocess.HookType_Pre,
		},
	}
}

func withPropagator(t *testing.T, p propagation.TextMapPropagator) {
	t.Helper()
	prev := gotel.GetTextMapPropagator()
	gotel.SetTextMapPropagator(p)
	t.Cleanup(func() { gotel.SetTextMapPropagator(prev) })
}

func buildObjectWithSpan(t *testing.T, sc trace.SpanContext) *coprocess.Object {
	t.Helper()
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
	require.NoError(t, err)

	cp := newMinimalCoProcessor()
	object, err := cp.BuildObject(req, nil, cp.Middleware.Spec)
	require.NoError(t, err)
	require.NotNil(t, object)
	return object
}

func makeSpanContext(t *testing.T) (sc trace.SpanContext, tid trace.TraceID, sid trace.SpanID) {
	t.Helper()
	var err error
	tid, err = trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	require.NoError(t, err)
	sid, err = trace.SpanIDFromHex("00f067aa0ba902b7")
	require.NoError(t, err)
	sc = trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return sc, tid, sid
}

func TestBuildObjectInjectsTraceParent_W3C(t *testing.T) {
	withPropagator(t, propagation.TraceContext{})

	sc, tid, sid := makeSpanContext(t)
	object := buildObjectWithSpan(t, sc)

	tp, ok := object.Metadata["traceparent"]
	require.True(t, ok)

	expected := fmt.Sprintf("00-%s-%s-%s", tid.String(), sid.String(), trace.FlagsSampled.String())
	assert.Equal(t, expected, tp)

	parts := strings.Split(tp, "-")
	assert.Len(t, parts, 4)
	assert.Equal(t, "00", parts[0])
	assert.Equal(t, tid.String(), parts[1])
	assert.Equal(t, sid.String(), parts[2])
}

func TestBuildObjectInjectsTraceParent_B3(t *testing.T) {
	withPropagator(t, b3prop.New(b3prop.WithInjectEncoding(b3prop.B3MultipleHeader)))

	sc, tid, sid := makeSpanContext(t)
	object := buildObjectWithSpan(t, sc)

	assert.Equal(t, tid.String(), object.Metadata["x-b3-traceid"])
	assert.Equal(t, sid.String(), object.Metadata["x-b3-spanid"])
	assert.Equal(t, "1", object.Metadata["x-b3-sampled"])

	_, hasTraceparent := object.Metadata["traceparent"]
	assert.False(t, hasTraceparent)
}

func TestBuildObjectNoTraceHeadersWhenNoSpan(t *testing.T) {
	withPropagator(t, propagation.TraceContext{})

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)

	cp := newMinimalCoProcessor()
	object, err := cp.BuildObject(req, nil, cp.Middleware.Spec)
	require.NoError(t, err)
	require.NotNil(t, object)

	_, hasTraceparent := object.Metadata["traceparent"]
	assert.False(t, hasTraceparent)
}

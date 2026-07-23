package escaper

import (
	"net/http"
	"net/http/httptest"
	"testing"

	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestNewFactory(t *testing.T) {
	tests := []struct {
		name         string
		options      []FactoryOption
		expectedType Type
		wantLog      bool
	}{
		{
			name:         "default factory",
			options:      nil,
			expectedType: TypeLegacy,
			wantLog:      false,
		},
		{
			name: "explicit skip type",
			options: []FactoryOption{
				WithType(TypeSkip),
			},
			expectedType: TypeSkip,
			wantLog:      false,
		},
		{
			name: "fallback to legacy on empty string",
			options: []FactoryOption{
				WithType(""),
			},
			expectedType: TypeLegacy,
			wantLog:      false,
		},
		{
			name: "fallback to legacy on unknown type",
			options: []FactoryOption{
				WithType("unknown_type"),
			},
			expectedType: TypeLegacy,
			wantLog:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, hook := logrustest.NewNullLogger()

			opts := append(tt.options, WithLogger(logger))
			f := NewFactory(opts...)

			assert.Equal(t, tt.expectedType, f.typ)
			assert.Equal(t, tt.wantLog, len(hook.AllEntries()) > 0)
		})
	}
}

func TestFactory_Make(t *testing.T) {
	tests := []struct {
		name          string
		factoryOpts   []FactoryOption
		setupRequest  func(*http.Request)
		expectEscaper string
	}{
		{
			name:          "default uses js escaper",
			factoryOpts:   nil,
			setupRequest:  func(*http.Request) {},
			expectEscaper: "js",
		},
		{
			name:          "global type skip forces skip escaper",
			factoryOpts:   []FactoryOption{WithType(TypeSkip)},
			setupRequest:  func(*http.Request) {},
			expectEscaper: "skip",
		},
		{
			name:        "x-skip-escaper header with value 1 skips",
			factoryOpts: nil,
			setupRequest: func(r *http.Request) {
				r.Header.Set(XSkipEscaper, "1")
			},
			expectEscaper: "skip",
		},
		{
			name:        "x-skip-escaper header with value true skips",
			factoryOpts: nil,
			setupRequest: func(r *http.Request) {
				r.Header.Set(XSkipEscaper, "true")
			},
			expectEscaper: "skip",
		},
		{
			name:        "x-skip-escaper header with value 0 does not skip",
			factoryOpts: nil,
			setupRequest: func(r *http.Request) {
				r.Header.Set(XSkipEscaper, "0")
			},
			expectEscaper: "js",
		},
		{
			name:        "content-type exact match skips",
			factoryOpts: []FactoryOption{WithSkipContentTypes("application/json")},
			setupRequest: func(r *http.Request) {
				r.Header.Set(ContentType, "application/json")
			},
			expectEscaper: "skip",
		},
		{
			name:        "content-type with parameters and whitespaces skips",
			factoryOpts: []FactoryOption{WithSkipContentTypes("application/json")},
			setupRequest: func(r *http.Request) {
				r.Header.Set(ContentType, "application/json ; charset=utf-8")
			},
			expectEscaper: "skip",
		},
		{
			name:        "content-type not in skip list does not skip",
			factoryOpts: []FactoryOption{WithSkipContentTypes("text/html")},
			setupRequest: func(r *http.Request) {
				r.Header.Set(ContentType, "application/json")
			},
			expectEscaper: "js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFactory(tt.factoryOpts...)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tt.setupRequest(req)

			escaper := f.Make(req)

			testInput := `<script>alert("test")</script>`
			result := escaper.Escape(testInput)

			if tt.expectEscaper == "skip" {
				assert.Equal(t, testInput, result)
			} else {
				assert.NotEqual(t, testInput, result)
				assert.Contains(t, result, `\u003Cscript\u003E`)
			}
		})
	}
}

func TestEscapers(t *testing.T) {
	input := `<script>alert("hello")</script>`

	assert.Equal(t, input, skipEscaper.Escape(input))

	expectedJS := `\u003Cscript\u003Ealert(\"hello\")\u003C/script\u003E`
	assert.Equal(t, expectedJS, jsEscaper.Escape(input))
}

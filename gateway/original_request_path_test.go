package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/otel"
	tyklog "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/test"
)

func TestOriginalRequestPath(t *testing.T) {
	t.Run("round-trip set and get returns stored path", func(t *testing.T) {
		tests := []struct {
			name string
			path string
		}{
			{"simple path", "/api/v1/users"},
			{"URL-encoded path preserved", "/api/v1/users/Mar%C3%ADa%20Santos"},
			{"trailing slash preserved", "/api/v1/users/"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.path, nil)
				ctxSetOriginalRequestPath(r, tt.path)
				got := ctxGetOriginalRequestPath(r)
				assert.Equal(t, tt.path, got)
			})
		}
	})

	t.Run("unset context returns empty string", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		got := ctxGetOriginalRequestPath(r)
		assert.Equal(t, "", got)
	})
}

func TestOriginalRequestPath_MainHTTPSpanAttribute(t *testing.T) {
	received := make(chan []byte, 1)
	otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received <- body
		w.WriteHeader(http.StatusOK)
	}, ":0")
	otelCollectorMock.Start()
	defer otelCollectorMock.Close()

	cfg := &otel.OpenTelemetry{BaseOpenTelemetry: otel.BaseOpenTelemetry{
		Enabled:           true,
		SpanProcessorType: "simple",
		ExporterConfig: otel.ExporterConfig{
			Exporter: "http",
			Endpoint: otelCollectorMock.URL,
		},
	}}
	provider := otel.InitOpenTelemetry(context.Background(), tyklog.Get(), cfg, "test-gw", "v1.0.0", false, "", false, nil)
	defer func() {
		_ = provider.Shutdown(context.Background())
	}()

	handler := &handleWrapper{
		router: otel.HTTPHandler("test-api", withOriginalPathSpanAttribute(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})), provider),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var payload []byte
	select {
	case payload = <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OpenTelemetry export")
	}

	require.NotEmpty(t, payload)
	assert.Contains(t, string(payload), "GET /api/v1/users")
	assert.True(t, bytes.Contains(payload, []byte("tyk.original_path")))
	assert.True(t, bytes.Contains(payload, []byte("/api/v1/users")))
}

func TestOriginalRequestPath_OnlyOnMainSpan_DetailedTracing(t *testing.T) {
	var mu sync.Mutex
	var payloads []byte
	otelCollectorMock := httpCollectorMock(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		mu.Lock()
		payloads = append(payloads, body...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}, ":0")
	otelCollectorMock.Start()
	defer otelCollectorMock.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.OpenTelemetry.Enabled = true
		globalConf.OpenTelemetry.Exporter = "http"
		globalConf.OpenTelemetry.Endpoint = otelCollectorMock.URL
		globalConf.OpenTelemetry.SpanProcessorType = "simple"
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/my-api/"
		spec.UseKeylessAccess = true
		spec.DetailedTracing = true
	})

	_, _ = ts.Run(t, test.TestCase{Path: "/my-api/", Code: http.StatusOK})

	// With the simple span processor, child (middleware) spans export synchronously
	// before the main HTTP span ends, so once the main span arrives all spans arrived.
	deadline := time.Now().Add(5 * time.Second)
	var exported []byte
	for {
		mu.Lock()
		exported = append([]byte(nil), payloads...)
		mu.Unlock()
		if bytes.Contains(exported, []byte("GET /my-api/")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for main HTTP span export")
		}
		time.Sleep(50 * time.Millisecond)
	}

	count := bytes.Count(exported, []byte("tyk.original_path"))
	assert.Equal(t, 1, count, "tyk.original_path must be set only on the main HTTP span, found %d occurrences", count)
}

package portal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/warpstreamlabs/bento/public/service"
)

// TestPortalWebhookOutput is a unit test for portal webhook output plugin
// Verifies: STK-REQ-081, SYS-REQ-169, SW-REQ-156
// SW-REQ-156:nominal:nominal
// SW-REQ-156:determinism:nominal
func TestPortalWebhookOutput(t *testing.T) {
	mockServer := httptest.NewServer(nil)
	var wg sync.WaitGroup

	mockServer.Config.Handler = portalMockHandlerGenerator(mockServer.URL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test-webhook-1":
			wg.Done()
			w.WriteHeader(http.StatusOK)
		case "/test-webhook-2":
			wg.Done()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	builder := service.NewStreamBuilder()
	err := builder.SetYAML(`input:
  generate:
    count: 1
    interval: ""
    mapping: 'root = "test message"'

output:
    portal_webhook:
      portal_url: "` + mockServer.URL + `"
      secret: "secret"
      event_type: "abc"`)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	stream, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build stream: %v", err)
	}

	// Expect webhook to be called 2 times
	wg.Add(2)

	if err := stream.Run(context.Background()); err != nil {
		t.Fatalf("Stream encountered an error: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for webhook calls")
	}
}

// Verifies: STK-REQ-081, SYS-REQ-169, SW-REQ-156
// STK-REQ-081:error_handling:negative
// SW-REQ-156:nominal:nominal
// SW-REQ-156:error_handling:nominal
// SW-REQ-156:error_handling:negative
func TestPortalOutputSendToWebhook(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    string
	}{
		{name: "success", statusCode: http.StatusAccepted, body: "accepted"},
		{name: "non-success", statusCode: http.StatusInternalServerError, body: "failed", wantErr: "received non-success code from webhook"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody string
			var gotHeader string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Fatalf("method = %s, want POST", r.Method)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("Content-Type = %q, want application/json", got)
				}
				gotHeader = r.Header.Get("X-Test")
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read request body: %v", err)
				}
				gotBody = string(body)
				w.WriteHeader(tt.statusCode)
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Fatalf("write response: %v", err)
				}
			}))
			defer server.Close()

			output := &portalOutput{conf: &portalOutputConfig{Headers: map[string]string{"X-Test": "portal"}}}
			err := output.sendToWebhook(server.URL, []byte(`{"event":"abc"}`))
			if tt.wantErr == "" && err != nil {
				t.Fatalf("sendToWebhook returned error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("sendToWebhook returned nil error, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("sendToWebhook error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			}
			if gotHeader != "portal" {
				t.Fatalf("X-Test header = %q, want portal", gotHeader)
			}
			if gotBody != `{"event":"abc"}` {
				t.Fatalf("body = %q, want %q", gotBody, `{"event":"abc"}`)
			}
		})
	}
}

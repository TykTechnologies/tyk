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

// Verifies: STK-REQ-081, SYS-REQ-169, SW-REQ-156
// MCDC SYS-REQ-169: portal_webhook_helpers_operation_terminal=T => TRUE
// MCDC SW-REQ-156: portal_webhook_helpers_operation_terminal=T => TRUE
// STK-REQ-081:STK-REQ-081-AC-01:acceptance
// STK-REQ-081:error_handling:negative
// SW-REQ-156:nominal:nominal
// SW-REQ-156:boundary:nominal
// SW-REQ-156:error_handling:nominal
// SW-REQ-156:error_handling:negative
// SW-REQ-156:determinism:nominal
func TestPortalWebhookHelpersReqProof(t *testing.T) {
	t.Run("client URL normalization", func(t *testing.T) {
		tests := []struct {
			name string
			in   string
			want string
		}{
			{name: "plain host", in: "http://portal.local", want: "http://portal.local/portal-api"},
			{name: "slash terminated", in: "http://portal.local/", want: "http://portal.local/portal-api"},
			{name: "already suffixed", in: "http://portal.local/portal-api", want: "http://portal.local/portal-api"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := NewClient(tt.in, "secret")
				if got.BaseURL != tt.want {
					t.Fatalf("BaseURL = %q, want %q", got.BaseURL, tt.want)
				}
				if got.Secret != "secret" {
					t.Fatalf("Secret = %q, want secret", got.Secret)
				}
			})
		}
	})

	mockServer := httptest.NewServer(nil)
	defer mockServer.Close()

	var webhookMu sync.Mutex
	var webhookCalls []string
	webhookHeaders := make(chan string, 2)

	mockServer.Config.Handler = portalMockHandlerGenerator(mockServer.URL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test-webhook-1", "/test-webhook-2":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read webhook body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			webhookMu.Lock()
			webhookCalls = append(webhookCalls, r.URL.Path+":"+string(body))
			webhookMu.Unlock()
			webhookHeaders <- r.Header.Get("X-Test")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Run("credential listing skips apps without webhook URLs", func(t *testing.T) {
		client := NewClient(mockServer.URL, "test-token")
		credentials, err := client.ListWebhookCredentials()
		if err != nil {
			t.Fatalf("ListWebhookCredentials returned error: %v", err)
		}
		if len(credentials) != 2 {
			t.Fatalf("credentials length = %d, want 2", len(credentials))
		}
		for _, credential := range credentials {
			if credential.WebhookURL == "" {
				t.Fatalf("credential for app %d has empty webhook URL", credential.AppID)
			}
		}
	})

	t.Run("bento output construction and matching webhook dispatch", func(t *testing.T) {
		builder := service.NewStreamBuilder()
		err := builder.SetYAML(`input:
  generate:
    count: 1
    interval: ""
    mapping: 'root = {"event":"abc"}'

output:
  portal_webhook:
    portal_url: "` + mockServer.URL + `"
    secret: "secret"
    event_type: "abc"
    headers:
      X-Test: "portal"`)
		if err != nil {
			t.Fatalf("SetYAML returned error: %v", err)
		}

		stream, err := builder.Build()
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}

		if err := stream.Run(context.Background()); err != nil {
			t.Fatalf("Run returned error: %v", err)
		}

		deadline := time.After(2 * time.Second)
		for i := 0; i < 2; i++ {
			select {
			case gotHeader := <-webhookHeaders:
				if gotHeader != "portal" {
					t.Fatalf("X-Test header = %q, want portal", gotHeader)
				}
			case <-deadline:
				t.Fatal("timeout waiting for matching webhook dispatches")
			}
		}

		webhookMu.Lock()
		defer webhookMu.Unlock()
		if len(webhookCalls) != 2 {
			t.Fatalf("webhook call count = %d, want 2", len(webhookCalls))
		}
	})

	t.Run("webhook non-success response returns local error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("failed")); err != nil {
				t.Fatalf("write response: %v", err)
			}
		}))
		defer server.Close()

		output := &portalOutput{conf: &portalOutputConfig{Headers: map[string]string{"X-Test": "portal"}}}
		err := output.sendToWebhook(server.URL, []byte(`{"event":"abc"}`))
		if err == nil {
			t.Fatal("sendToWebhook returned nil error, want non-success error")
		}
		if !strings.Contains(err.Error(), "received non-success code from webhook") {
			t.Fatalf("sendToWebhook error = %q, want non-success substring", err.Error())
		}
	})
}

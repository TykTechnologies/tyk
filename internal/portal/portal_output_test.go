package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/warpstreamlabs/bento/public/service"
)

// TestPortalWebhookOutput is a unit test for portal webhook output plugin
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

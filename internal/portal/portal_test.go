package portal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func portalMockHandlerGenerator(serverURL string, customHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/portal-api/apps":
			// Mock response for list of apps with IDs 1, 2, and 3
			if _, err := fmt.Fprintf(w, `[{"ID":1,"Name":"Test App 1"},{"ID":2,"Name":"Test App 2"},{"ID":3,"Name":"Test App 3"}]`); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		case "/portal-api/apps/1":
			// Mock response for app 1 detail with webhook credentials
			if _, err := fmt.Fprintf(w, `{"ID": 1, "AccessRequests": [{"WebhookEventTypes": "abc,bar,foo", "WebhookSecret": "test", "WebhookURL": "%s/test-webhook-1"}]}`, serverURL); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		case "/portal-api/apps/2":
			// App 2 detail without webhook (empty array or null could represent no webhooks)
			if _, err := fmt.Fprintf(w, `{"ID": 2, "AccessRequests": []}`); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		case "/portal-api/apps/3":
			// Mock response for app 3 detail with webhook credentials
			if _, err := fmt.Fprintf(w, `{"ID": 3, "AccessRequests": [{"WebhookEventTypes": "abc,xyz", "WebhookSecret": "secret", "WebhookURL": "%s/test-webhook-2"}]}`, serverURL); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		default:
			if customHandler != nil {
				customHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestListWebhookCredentialsMultipleApps(t *testing.T) {
	// Mock server to return a list of multiple apps and details for individual apps
	mockServer := httptest.NewServer(nil)
	mockServer.Config.Handler = portalMockHandlerGenerator(mockServer.URL, nil)

	defer mockServer.Close()

	client := NewClient(mockServer.URL, "test-token")

	expected := []WebhookCredential{
		{
			AppID:             1,
			AppName:           "Test App 1",
			WebhookEventTypes: "abc,bar,foo",
			WebhookSecret:     "test",
			WebhookURL:        mockServer.URL + "/test-webhook-1",
		},
		{
			AppID:             3,
			AppName:           "Test App 3",
			WebhookEventTypes: "abc,xyz",
			WebhookSecret:     "secret",
			WebhookURL:        mockServer.URL + "/test-webhook-2",
		},
	}

	webhookCredentials, err := client.ListWebhookCredentials()
	if err != nil {
		t.Fatalf("Expected no error, got %s", err)
	}

	if len(webhookCredentials) != len(expected) {
		t.Fatalf("Expected %d webhook credentials, got %d", len(expected), len(webhookCredentials))
	}

	for i, wc := range webhookCredentials {
		exp := expected[i]
		if wc.WebhookURL != exp.WebhookURL || wc.WebhookEventTypes != exp.WebhookEventTypes {
			t.Errorf("Expected webhook credential %v, got %v", exp, wc)
		}
	}
}

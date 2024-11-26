package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockServer struct {
	*httptest.Server
}

func newMockServer() *mockServer {
	ms := &mockServer{}
	ms.Server = httptest.NewServer(http.HandlerFunc(mockHandler))
	return ms
}

func mockHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/portal/webhooks":
		response := struct {
			Apps []struct {
				Name            string          `json:"name"`
				AccessRequests  []AccessRequest `json:"access_requests"`
				UserID          int            `json:"user_id"`
			} `json:"apps"`
		}{
			Apps: []struct {
				Name            string          `json:"name"`
				AccessRequests  []AccessRequest `json:"access_requests"`
				UserID          int            `json:"user_id"`
			}{
				{
					Name: "Webhook",
					AccessRequests: []AccessRequest{
						{
							ID:                5,
							Status:            "approved",
							WebhookURL:        "http://test1.com",
							WebhookEventTypes: "event1",
							WebhookSecret:     "secret1",
							Credentials: []Credential{
								{
									ID:             5,
									Credential:     "cred1",
									CredentialHash: "hash1",
								},
							},
						},
					},
					UserID: 1,
				},
				{
					Name: "Webhook2",
					AccessRequests: []AccessRequest{
						{
							ID:                6,
							Status:            "approved",
							WebhookURL:        "http://test2.com",
							WebhookEventTypes: "event2",
							WebhookSecret:     "secret2",
							Credentials: []Credential{
								{
									ID:             6,
									Credential:     "cred2",
									CredentialHash: "hash2",
								},
							},
						},
					},
					UserID: 2,
				},
			},
		}

		json.NewEncoder(w).Encode(response)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestPortalClientListWebhookCredentials(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	webhooks, err := client.ListWebhookCredentials(context.Background())
	require.NoError(t, err)
	require.Len(t, webhooks, 2)

	assert.Equal(t, "http://test1.com", webhooks[0].WebhookURL)
	assert.Equal(t, "event1", webhooks[0].WebhookEventTypes)
	assert.Equal(t, "secret1", webhooks[0].WebhookSecret)
	assert.Equal(t, "cred1", webhooks[0].Credential)
	assert.Equal(t, "hash1", webhooks[0].CredentialHash)

	assert.Equal(t, "http://test2.com", webhooks[1].WebhookURL)
	assert.Equal(t, "event2", webhooks[1].WebhookEventTypes)
	assert.Equal(t, "secret2", webhooks[1].WebhookSecret)
	assert.Equal(t, "cred2", webhooks[1].Credential)
	assert.Equal(t, "hash2", webhooks[1].CredentialHash)
}

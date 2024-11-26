package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/warpstreamlabs/bento/public/service"
)

type mockPortalClient struct {
	webhooks   []WebhookCredential
	callCount  int
	shouldFail bool
	mu         sync.Mutex
}

func (m *mockPortalClient) ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.callCount++
	if m.shouldFail {
		return nil, fmt.Errorf("mock client failed")
	}
	return m.webhooks, nil
}

func (m *mockPortalClient) GetWebhookCredential(ctx context.Context, id string) (*WebhookCredential, error) {
	// implement GetWebhookCredential method
	return nil, nil
}

func (m *mockPortalClient) CreateWebhookCredential(ctx context.Context, credential *WebhookCredential) (*WebhookCredential, error) {
	// implement CreateWebhookCredential method
	return nil, nil
}

func (m *mockPortalClient) UpdateWebhookCredential(ctx context.Context, id string, credential *WebhookCredential) (*WebhookCredential, error) {
	// implement UpdateWebhookCredential method
	return nil, nil
}

func (m *mockPortalClient) DeleteWebhookCredential(ctx context.Context, id string) error {
	// implement DeleteWebhookCredential method
	return nil
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		default_ time.Duration
		want     time.Duration
	}{
		{
			name:     "empty string returns default",
			input:    "",
			default_: time.Minute,
			want:     time.Minute,
		},
		{
			name:     "invalid duration returns default",
			input:    "invalid",
			default_: time.Minute,
			want:     time.Minute,
		},
		{
			name:     "valid duration is parsed",
			input:    "2m",
			default_: time.Minute,
			want:     2 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDuration(tt.input, tt.default_)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPortalOutputFiltering(t *testing.T) {
	// Create test server to receive webhook requests
	var receivedRequests int
	var requestsMu sync.Mutex
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsMu.Lock()
		receivedRequests++
		requestsMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create test webhooks with different credentials and event types
	webhooks := []WebhookCredential{
		{
			WebhookURL:        server.URL + "/hook1",
			WebhookEventTypes: "foo,bar",
			WebhookSecret:     "secret1",
			Credential:        "eyJvcmciOiI2NTE3MGY4MWVhOWJmNjA0YmI0NzRjMDIiLCJpZCI6Ijg1MDFjMGYzZTYwZjQ2YTk4MWJkMjk5M2NkNzBhNTQwIiwiaCI6Im11cm11cjY0In0=",
			CredentialHash:    "15f9c8e837a34abb",
		},
		{
			WebhookURL:        server.URL + "/hook2",
			WebhookEventTypes: "baz",
			WebhookSecret:     "secret2",
			Credential:        "different-credential",
			CredentialHash:    "different-hash",
		},
	}

	mockClient := &mockPortalClient{webhooks: webhooks}

	tests := []struct {
		name           string
		config         *portalOutputConfig
		message        *service.Message
		expectRequests int
	}{
		{
			name: "filter by credential matches",
			config: &portalOutputConfig{
				PortalURL:      server.URL,
				Secret:         "test-secret",
				EventType:      "foo",
				Credential:     "eyJvcmciOiI2NTE3MGY4MWVhOWJmNjA0YmI0NzRjMDIiLCJpZCI6Ijg1MDFjMGYzZTYwZjQ2YTk4MWJkMjk5M2NkNzBhNTQwIiwiaCI6Im11cm11cjY0In0=",
				CredentialHash: "15f9c8e837a34abb",
			},
			message: func() *service.Message {
				msg := service.NewMessage([]byte("test message"))
				msg.MetaSet("credential", "eyJvcmciOiI2NTE3MGY4MWVhOWJmNjA0YmI0NzRjMDIiLCJpZCI6Ijg1MDFjMGYzZTYwZjQ2YTk4MWJkMjk5M2NkNzBhNTQwIiwiaCI6Im11cm11cjY0In0=")
				msg.MetaSet("credential_hash", "15f9c8e837a34abb")
				return msg
			}(),
			expectRequests: 1,
		},
		{
			name: "filter by event type matches",
			config: &portalOutputConfig{
				PortalURL: server.URL,
				Secret:    "test-secret",
				EventType: "bar",
			},
			message:        service.NewMessage([]byte("test message")),
			expectRequests: 1,
		},
		{
			name: "filter by credential hash matches",
			config: &portalOutputConfig{
				PortalURL:      server.URL,
				Secret:         "test-secret",
				EventType:      "foo",
				CredentialHash: "15f9c8e837a34abb",
			},
			message: func() *service.Message {
				msg := service.NewMessage([]byte("test message"))
				msg.MetaSet("credential_hash", "15f9c8e837a34abb")
				return msg
			}(),
			expectRequests: 1,
		},
		{
			name: "no match - wrong credential",
			config: &portalOutputConfig{
				PortalURL:  server.URL,
				Secret:     "test-secret",
				EventType:  "foo",
				Credential: "wrong-credential",
			},
			message: func() *service.Message {
				msg := service.NewMessage([]byte("test message"))
				msg.MetaSet("credential", "wrong-credential")
				return msg
			}(),
			expectRequests: 0,
		},
		{
			name: "no match - wrong event type",
			config: &portalOutputConfig{
				PortalURL: server.URL,
				Secret:    "test-secret",
				EventType: "nonexistent",
			},
			message:        service.NewMessage([]byte("test message")),
			expectRequests: 0,
		},
		{
			name: "no match - wrong credential hash",
			config: &portalOutputConfig{
				PortalURL:      server.URL,
				Secret:         "test-secret",
				EventType:      "foo",
				CredentialHash: "wrong-hash",
			},
			message: func() *service.Message {
				msg := service.NewMessage([]byte("test message"))
				msg.MetaSet("credential_hash", "wrong-hash")
				return msg
			}(),
			expectRequests: 0,
		},
		{
			name: "match multiple webhooks - same event type",
			config: &portalOutputConfig{
				PortalURL: server.URL,
				Secret:    "test-secret",
				EventType: "foo",
			},
			message:        service.NewMessage([]byte("test message")),
			expectRequests: 1, // Should match the first webhook with foo event type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestsMu.Lock()
			receivedRequests = 0
			requestsMu.Unlock()

			output := &portalOutput{
				config:       tt.config,
				portalClient: mockClient,
				httpClient:   &http.Client{},
			}

			err := output.Write(context.Background(), tt.message)
			require.NoError(t, err)

			// Wait for async operations
			time.Sleep(100 * time.Millisecond)

			requestsMu.Lock()
			assert.Equal(t, tt.expectRequests, receivedRequests, 
				"expected %d webhook requests, got %d", tt.expectRequests, receivedRequests)
			requestsMu.Unlock()
		})
	}
}

func TestPortalOutputContextCancellation(t *testing.T) {
	// Create a slow server that will trigger timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhooks := []WebhookCredential{
		{
			WebhookURL:        server.URL,
			WebhookEventTypes: "test-event",
		},
	}

	mockClient := &mockPortalClient{webhooks: webhooks}

	output := &portalOutput{
		config: &portalOutputConfig{
			PortalURL: server.URL,
			Secret:    "test-secret",
			EventType: "test-event",
			Timeout:   "100ms",
		},
		portalClient: mockClient,
		httpClient:   &http.Client{Timeout: 100 * time.Millisecond},
	}

	msg := service.NewMessage([]byte("test message"))
	err := output.Write(context.Background(), msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestPortalOutputDeveloperIDFilter(t *testing.T) {
	// Create test server to receive webhook requests
	var receivedRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequest = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhooks := []WebhookCredential{
		{
			WebhookURL:        server.URL,
			WebhookEventTypes: "test-event",
			UserID:            123,
		},
		{
			WebhookURL:        server.URL,
			WebhookEventTypes: "test-event",
			UserID:            456,
		},
	}

	tests := []struct {
		name        string
		developerID string
		shouldSend  bool
	}{
		{
			name:        "matching developer ID",
			developerID: "123",
			shouldSend:  true,
		},
		{
			name:        "non-matching developer ID",
			developerID: "789",
			shouldSend:  false,
		},
		{
			name:        "empty developer ID in config",
			developerID: "",
			shouldSend:  true,
		},
		{
			name:        "invalid developer ID format",
			developerID: "not-a-number",
			shouldSend:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedRequest = false
			mockClient := &mockPortalClient{webhooks: webhooks}
			output := &portalOutput{
				config: &portalOutputConfig{
					EventType:   "test-event",
					DeveloperID: tt.developerID,
					PortalURL:   server.URL,
				},
				portalClient: mockClient,
				httpClient:   http.DefaultClient,
			}

			msg := &service.Message{}
			err := output.Write(context.Background(), msg)
			require.NoError(t, err)
			assert.Equal(t, tt.shouldSend, receivedRequest, "request should have been sent: %v", tt.shouldSend)
		})
	}
}

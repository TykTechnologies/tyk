package portal

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockPortalClientWithDelay struct {
	webhooks   []WebhookCredential
	callCount  int
	delay      time.Duration
	returnErr  error
	mu         sync.Mutex
}

func (m *mockPortalClientWithDelay) ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}
	
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return m.webhooks, nil
}

func TestCachedClient(t *testing.T) {
	ctx := context.Background()
	
	webhooks := []WebhookCredential{
		{
			WebhookURL:        "https://webhook.site/test1",
			WebhookEventTypes: "bar,foo",
			WebhookSecret:     "test",
		},
	}

	tests := []struct {
		name     string
		ttl      time.Duration
		delay    time.Duration
		webhooks []WebhookCredential
	}{
		{
			name:     "cache hit",
			ttl:      time.Second,
			webhooks: webhooks,
		},
		{
			name:     "cache miss with background refresh",
			ttl:      time.Millisecond,
			delay:    100 * time.Millisecond,
			webhooks: webhooks,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPortalClientWithDelay{
				webhooks: tt.webhooks,
				delay:    tt.delay,
			}

			client := NewCachedClient(mock, tt.ttl)

			// First call should populate cache
			result1, err := client.ListWebhookCredentials(ctx)
			if err != nil {
				t.Fatalf("First call failed: %v", err)
			}
			if len(result1) != len(tt.webhooks) {
				t.Errorf("Expected %d webhooks, got %d", len(tt.webhooks), len(result1))
			}
			initialCallCount := mock.callCount

			// Immediate second call should hit cache
			_, err = client.ListWebhookCredentials(ctx)
			if err != nil {
				t.Fatalf("Second call failed: %v", err)
			}
			if mock.callCount > initialCallCount {
				t.Error("Cache was not used for second call")
			}

			// Wait for TTL to expire
			time.Sleep(tt.ttl + time.Millisecond)

			// Third call should trigger background refresh but return cached data
			result3, err := client.ListWebhookCredentials(ctx)
			if err != nil {
				t.Fatalf("Third call failed: %v", err)
			}
			if len(result3) != len(tt.webhooks) {
				t.Errorf("Expected %d webhooks, got %d", len(tt.webhooks), len(result3))
			}

			// Wait for background refresh to complete
			time.Sleep(tt.delay + 100*time.Millisecond)

			// Verify that background refresh occurred
			if mock.callCount <= initialCallCount {
				t.Error("Background refresh did not occur")
			}
		})
	}
}

func TestCachedClientConcurrency(t *testing.T) {
	ctx := context.Background()
	
	webhooks := []WebhookCredential{
		{
			WebhookURL:        "https://webhook.site/test1",
			WebhookEventTypes: "bar,foo",
			WebhookSecret:     "test",
		},
	}

	mock := &mockPortalClientWithDelay{
		webhooks: webhooks,
		delay:    100 * time.Millisecond,
	}

	client := NewCachedClient(mock, time.Second)

	// Run multiple goroutines to test concurrent access
	concurrency := 10
	errCh := make(chan error, concurrency)

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, err := client.ListWebhookCredentials(ctx)
			if err != nil {
				errCh <- err
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errCh)

	// Check for any errors
	for err := range errCh {
		t.Errorf("Concurrent call failed: %v", err)
	}

	// Verify that we didn't make too many calls to the underlying client
	if mock.callCount > 1 {
		t.Errorf("Too many calls to underlying client: %d", mock.callCount)
	}
}

func TestCachedClientContextCancellation(t *testing.T) {
	webhooks := []WebhookCredential{
		{
			WebhookURL:        "https://webhook.site/test1",
			WebhookEventTypes: "bar,foo",
			WebhookSecret:     "test",
		},
	}

	mock := &mockPortalClientWithDelay{
		webhooks: webhooks,
		delay:    100 * time.Millisecond,
	}

	client := NewCachedClient(mock, time.Second)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// This call should fail due to context timeout
	_, err := client.ListWebhookCredentials(ctx)
	if err == nil {
		t.Error("Expected context timeout error, got nil")
	}
}

func TestSharedCache(t *testing.T) {
	ctx := context.Background()
	
	// Reset global manager for clean test
	globalManager = nil
	globalManagerOnce = sync.Once{}

	webhooks := []WebhookCredential{
		{
			WebhookURL:        "https://webhook.site/test1",
			WebhookEventTypes: "bar,foo",
			WebhookSecret:     "test",
		},
	}

	mock := &mockPortalClientWithDelay{
		webhooks: webhooks,
		delay:    100 * time.Millisecond,
	}

	// Create multiple outputs with same portal URL and secret
	portalURL := "https://portal.test"
	secret := "test-secret"
	ttl := time.Second

	// Create first client
	client1 := GetCacheManager().GetOrCreateCache(portalURL, secret, ttl)
	// Override the underlying client with our mock
	client1.client = mock

	// Create second client with same parameters
	client2 := GetCacheManager().GetOrCreateCache(portalURL, secret, ttl)

	// Verify that both clients share the same cache
	if client1 != client2 {
		t.Error("Expected clients to share the same cache instance")
	}

	// Make a request with first client
	result1, err := client1.ListWebhookCredentials(ctx)
	if err != nil {
		t.Fatalf("First client call failed: %v", err)
	}
	if len(result1) != len(webhooks) {
		t.Errorf("Expected %d webhooks, got %d", len(webhooks), len(result1))
	}
	initialCallCount := mock.callCount

	// Make a request with second client
	_, err = client2.ListWebhookCredentials(ctx)
	if err != nil {
		t.Fatalf("Second client call failed: %v", err)
	}

	// Verify that second request used cache
	if mock.callCount > initialCallCount {
		t.Error("Cache was not shared between clients")
	}

	// Cleanup
	GetCacheManager().Stop()
}

package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client defines the interface for interacting with the Portal API.
// It provides methods to manage webhook credentials, allowing the system
// to dynamically discover and manage webhook endpoints.
type Client interface {
	ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error)
}

// portalClient implements the Client interface for the Portal API.
// It handles authentication and communication with the API endpoints.
type portalClient struct {
	baseURL    string        // Base URL of the Portal API
	secret     string        // Authentication secret for API requests
	httpClient *http.Client  // HTTP client for making API requests
}

// NewClient creates a new Portal API client with the specified base URL and secret.
// It returns an interface to allow for easy mocking in tests and flexibility
// in implementation.
func NewClient(baseURL, secret string) Client {
	return &portalClient{
		baseURL:    baseURL,
		secret:     secret,
		httpClient: &http.Client{},
	}
}

// ListWebhookCredentials retrieves all webhook credentials from the Portal API.
// It fetches the list of apps and their associated access requests, then extracts
// webhook credentials from approved access requests.
func (c *portalClient) ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error) {
	// Construct the API URL for webhook listing
	url := fmt.Sprintf("%s/api/portal/webhooks", c.baseURL)
	
	// Create a new request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Add authentication header
	req.Header.Set("Authorization", c.secret)

	// Make the API request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the API response
	var response struct {
		Apps []struct {
			AccessRequests []AccessRequest `json:"access_requests"`
			UserID        int             `json:"user_id"`
			Name          string          `json:"name"`
			Description   string          `json:"description"`
			CreatedAt     string          `json:"created_at"`
			ID            int             `json:"id"`
		} `json:"apps"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Extract webhook credentials from approved access requests
	var webhooks []WebhookCredential
	for _, app := range response.Apps {
		for _, ar := range app.AccessRequests {
			// Skip non-approved access requests
			if ar.Status != "approved" {
				continue
			}
			// Create webhook credentials for each credential in the access request
			for _, cred := range ar.Credentials {
				webhooks = append(webhooks, WebhookCredential{
					WebhookURL:        ar.WebhookURL,
					WebhookEventTypes: ar.WebhookEventTypes,
					WebhookSecret:     ar.WebhookSecret,
					Credential:        cred.Credential,
					CredentialHash:    cred.CredentialHash,
					UserID:            app.UserID,
				})
			}
		}
	}

	return webhooks, nil
}

// AccessRequest represents an access request in the Portal API.
// It contains information about webhook configuration and associated credentials.
type AccessRequest struct {
	ID                int          `json:"id"`              // Unique identifier for the access request
	Status            string       `json:"status"`          // Status of the access request (e.g., "approved")
	WebhookURL        string       `json:"webhook_url"`     // URL where webhook events will be sent
	WebhookEventTypes string       `json:"webhook_event_types"` // Comma-separated list of event types
	WebhookSecret     string       `json:"webhook_secret"`  // Secret for webhook authentication
	Credentials       []Credential `json:"credentials"`     // List of associated credentials
}

// Credential represents a credential in the Portal API.
// Each credential can be associated with one or more webhooks.
type Credential struct {
	ID             int    `json:"id"`              // Unique identifier for the credential
	Credential     string `json:"credential"`      // The actual credential value
	CredentialHash string `json:"credential_hash"` // Hash of the credential for verification
}

// WebhookCredential represents a complete webhook configuration.
// It combines webhook details with a specific credential for event delivery.
type WebhookCredential struct {
	WebhookURL        string `json:"webhook_url"`         // URL where events will be sent
	WebhookEventTypes string `json:"webhook_event_types"` // Event types this webhook handles
	WebhookSecret     string `json:"webhook_secret"`      // Secret for webhook authentication
	Credential        string `json:"credential"`          // Associated credential
	CredentialHash    string `json:"credential_hash"`     // Hash of the credential
	UserID            int    `json:"user_id"`             // User ID associated with the webhook credential
}

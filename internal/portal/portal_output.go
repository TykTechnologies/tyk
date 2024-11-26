package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/warpstreamlabs/bento/public/service"
)

const (
	defaultCacheTTL = 1 * time.Minute
	defaultTimeout  = 10 * time.Second
)

// portalOutputConfig defines the configuration for portal webhook output.
// It specifies how messages should be filtered and delivered to webhooks.
type portalOutputConfig struct {
	PortalURL      string            // Base URL of the portal API
	Secret         string            // Authentication secret for portal API
	EventType      string            // Type of events to filter (if specified)
	Credential     string            // Specific credential to filter (if specified)
	CredentialHash string            // Specific credential hash to filter (if specified)
	DeveloperID    string            // Developer ID to filter (if specified)
	Headers        map[string]string // Additional headers to include in webhook requests
	CacheTTL       string            // Duration to cache webhook credentials
	Timeout        string            // Timeout for webhook requests
}

// parseDuration safely parses a duration string, returning a default value
// if the string is empty or invalid
func parseDuration(s string, defaultDur time.Duration) time.Duration {
	if s == "" {
		return defaultDur
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultDur
	}
	return d
}

// portalOutput implements a bento output that sends messages to portal webhooks.
// It maintains a cache of webhook credentials and filters messages based on
// configured criteria before sending them to matching webhooks.
type portalOutput struct {
	config       *portalOutputConfig // Configuration for this output
	portalClient Client              // Client for interacting with portal API
	httpClient   *http.Client        // HTTP client for making webhook requests
	mu           sync.RWMutex        // Protects access to internal state
}

// Connect initializes the portal output
func (p *portalOutput) Connect(ctx context.Context) error {
	return nil
}

// Write processes a message and sends it to matching webhooks.
// It first checks if the message matches configured filters,
// then sends the message to all matching webhook endpoints.
func (p *portalOutput) Write(ctx context.Context, msg *service.Message) error {
	if !p.shouldProcess(*msg) {
		return nil
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return p.sendToWebhook(ctx, p.config.PortalURL, data)
}

// shouldProcess determines if a message should be processed based on configured filters.
// It checks webhook credentials against configured filters for:
// - Event type
// - Credential
// - Credential hash
// Returns true if the message matches all specified filters.
func (p *portalOutput) shouldProcess(msg service.Message) bool {
	// Fetch webhook credentials from the portal API
	webhooks, err := p.portalClient.ListWebhookCredentials(context.Background())
	if err != nil {
		// If there's an error fetching credentials, skip processing this message
		return false
	}

	// Iterate over the fetched webhooks and check if any match the configured filters
	for _, webhook := range webhooks {
		// Check event type filter
		if p.config.EventType != "" {
			// Split the webhook's event types into a slice for easier comparison
			eventTypes := strings.Split(webhook.WebhookEventTypes, ",")
			// Check if the configured event type matches any of the webhook's event types
			eventTypeMatch := false
			for _, et := range eventTypes {
				if strings.TrimSpace(et) == p.config.EventType {
					eventTypeMatch = true
					break
				}
			}
			// If the event type doesn't match, skip this webhook
			if !eventTypeMatch {
				continue
			}
		}

		// Check credential filter
		if p.config.Credential != "" {
			// If the webhook's credential doesn't match the configured credential, skip this webhook
			if webhook.Credential != p.config.Credential {
				continue
			}
		}

		// Check credential hash filter
		if p.config.CredentialHash != "" {
			// If the webhook's credential hash doesn't match the configured credential hash, skip this webhook
			if webhook.CredentialHash != p.config.CredentialHash {
				continue
			}
		}

		// Check developer ID filter
		if p.config.DeveloperID != "" {
			devID, err := strconv.Atoi(p.config.DeveloperID)
			if err != nil {
				// If developer ID is not a valid number, skip this webhook
				return false
			}
			if webhook.UserID != devID {
				continue
			}
		}

		// If we've reached this point, all filters match, so return true
		return true
	}

	// If we've iterated over all webhooks and none match, return false
	return false
}

// sendToWebhook sends a message to a webhook endpoint.
// It constructs an HTTP request with the message data and sends it to the specified URL.
func (p *portalOutput) sendToWebhook(ctx context.Context, url string, data []byte) error {
	// Create a new HTTP request with the message data
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	// Set the Content-Type header to application/json
	req.Header.Set("Content-Type", "application/json")
	// Add any additional headers specified in the configuration
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	// Send the request using the HTTP client
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode >= 400 {
		// If the status code is 400 or higher, read the response body and return an error
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// If the status code is 200 or lower, return nil
	return nil
}

// Close is a no-op for this output
func (p *portalOutput) Close(ctx context.Context) error {
	return nil
}

// portalOutputConfigSpec returns a ConfigSpec for the portal output.
// It defines the configuration fields and their descriptions.
func portalOutputConfigSpec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Summary("Posts messages to dynamically fetched webhooks based on event type and filters.").
		Description("This output plugin fetches webhooks based on a specified event type and filters, then posts messages to them.").
		Field(service.NewStringField("portal_url").Description("The API URL of the Portal.")).
		Field(service.NewStringField("secret").Description("The secret key for accessing the API.")).
		Field(service.NewStringField("event_type").Description("The event type to filter the webhooks by.")).
		Field(service.NewStringField("credential").Optional().Description("Filter messages by credential")).
		Field(service.NewStringField("credential_hash").Optional().Description("Filter messages by credential hash")).
		Field(service.NewStringField("developer_id").Optional().Description("Filter messages by developer ID")).
		Field(service.NewStringMapField("headers").Optional().Description("Headers to add to the request.")).
		Field(service.NewStringField("cache_ttl").Optional().Description("Duration for caching portal webhook credentials (e.g. '1m', '30s'). Defaults to 1 minute if not specified.")).
		Field(service.NewStringField("timeout").Optional().Description("Request timeout duration (e.g. '5s', '1m'). Defaults to 10 seconds if not specified."))
}

func init() {
	err := service.RegisterOutput(
		"portal_webhook",
		portalOutputConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Output, int, error) {
			portalConfig := &portalOutputConfig{}

			// Extract required fields
			portalURL, err := conf.FieldString("portal_url")
			if err != nil {
				return nil, 0, err
			}
			portalConfig.PortalURL = portalURL

			secret, err := conf.FieldString("secret")
			if err != nil {
				return nil, 0, err
			}
			portalConfig.Secret = secret

			eventType, err := conf.FieldString("event_type")
			if err != nil {
				return nil, 0, err
			}
			portalConfig.EventType = eventType

			// Extract optional fields
			if credential, err := conf.FieldString("credential"); err == nil {
				portalConfig.Credential = credential
			}

			if credentialHash, err := conf.FieldString("credential_hash"); err == nil {
				portalConfig.CredentialHash = credentialHash
			}

			if developerID, err := conf.FieldString("developer_id"); err == nil {
				portalConfig.DeveloperID = developerID
			}

			if headers, err := conf.FieldStringMap("headers"); err == nil {
				portalConfig.Headers = headers
			}

			if cacheTTL, err := conf.FieldString("cache_ttl"); err == nil {
				portalConfig.CacheTTL = cacheTTL
			}

			if timeout, err := conf.FieldString("timeout"); err == nil {
				portalConfig.Timeout = timeout
			}

			client := NewClient(portalConfig.PortalURL, portalConfig.Secret)
			output := &portalOutput{
				config:       portalConfig,
				portalClient: client,
				httpClient:   &http.Client{},
			}

			return output, 1, nil
		})
	if err != nil {
		panic(err)
	}
}

package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const applicationJSON = "application/json"

// Client defines the interface for interacting with the Portal API.
// It provides methods to manage webhook credentials, allowing the system
// to dynamically discover and manage webhook endpoints.
type Client interface {
	ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error)
}

// portalClient implements the Client interface for the Portal API.
// It handles authentication and communication with the API endpoints.
type portalClient struct {
	baseURL    string
	secret     string
	httpClient *http.Client
}

// NewClient creates a new Portal API client with the specified base URL and secret.
// It returns an interface to allow for easy mocking in tests and flexibility
// in implementation.
func NewClient(baseURL, secret string) Client {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	if !strings.HasSuffix(baseURL, "portal-api/") {
		baseURL += "portal-api/"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &portalClient{
		baseURL:    baseURL,
		secret:     secret,
		httpClient: &http.Client{},
	}
}

// App represents the structure of an application from the developer portal
type App struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	UserID      int    `json:"user_id"`
}

// AppDetail includes detailed information about an application, including webhooks
type AppDetail struct {
	AccessRequests []struct {
		ActiveSubscription bool     `json:"ActiveSubscription"`
		AuthType           string   `json:"AuthType"`
		AuthTypes          []string `json:"AuthTypes"`
		Catalogue          string   `json:"Catalogue"`
		CertificateID      int      `json:"CertificateID"`
		Client             string   `json:"Client"`
		Credentials        []struct {
			AccessRequest              string `json:"AccessRequest"`
			Credential                 string `json:"Credential"`
			CredentialHash             string `json:"CredentialHash"`
			DCRRegistrationAccessToken string `json:"DCRRegistrationAccessToken"`
			DCRRegistrationClientURI   string `json:"DCRRegistrationClientURI"`
			DCRResponse                string `json:"DCRResponse"`
			Expires                    string `json:"Expires"`
			GrantType                  string `json:"GrantType"`
			ID                         int    `json:"ID"`
			JWKSURI                    string `json:"JWKSURI"`
			OAuthClientID              string `json:"OAuthClientID"`
			OAuthClientSecret          string `json:"OAuthClientSecret"`
			RedirectURI                string `json:"RedirectURI"`
			ResponseType               string `json:"ResponseType"`
			Scope                      string `json:"Scope"`
			TokenEndpoints             string `json:"TokenEndpoints"`
		} `json:"Credentials"`
		DCREnabled           bool        `json:"DCREnabled"`
		DCRTemplateID        int         `json:"DCRTemplateID"`
		ID                   int         `json:"ID"`
		Plan                 string      `json:"Plan"`
		PolicyService        []string    `json:"PolicyService"`
		Products             interface{} `json:"Products"`
		ProviderID           int         `json:"ProviderID"`
		ProvisionImmediately bool        `json:"ProvisionImmediately"`
		Status               string      `json:"Status"`
		User                 string      `json:"User"`
		WebhookEventTypes    string      `json:"WebhookEventTypes"`
		WebhookSecret        string      `json:"WebhookSecret"`
		WebhookURL           string      `json:"WebhookURL"`
	} `json:"AccessRequests"`
	CreatedAt    string `json:"CreatedAt"`
	Description  string `json:"Description"`
	ID           int    `json:"ID"`
	Name         string `json:"Name"`
	RedirectURLs string `json:"RedirectURLs"`
	UserID       int    `json:"UserID"`
}

// WebhookCredential represents a complete webhook configuration.
// It combines webhook details with a specific credential for event delivery.
type WebhookCredential struct {
	WebhookURL        string `json:"webhook_url"`
	WebhookEventTypes string `json:"webhook_event_types"`
	WebhookSecret     string `json:"webhook_secret"`
	Credential        string `json:"credential"`
	CredentialHash    string `json:"credential_hash"`
	UserID            int    `json:"user_id"`
}

// ListWebhookCredentials retrieves all webhook credentials from the Portal API.
// It fetches the list of apps and their associated access requests, then extracts
// webhook credentials from approved access requests.
func (c *portalClient) ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error) {
	var allApps []App
	for page := 1; ; page++ {
		apps, err := c.fetchApps(ctx, page)
		if err != nil {
			log.Errorf("Error fetching apps on page %d: %v", page, err)
			return nil, err
		}

		log.Infof("Fetched %d apps from page %d", len(apps), page)
		allApps = append(allApps, apps...)

		if len(apps) < 10 {
			log.Infof("Finished fetching apps, total: %d", len(allApps))
			break
		}
	}

	log.Infof("Total number of apps fetched: %d", len(allApps))

	var webhookCredentials []WebhookCredential
	for _, app := range allApps {
		log.Infof("Processing app ID %d", app.ID)

		detail, err := c.fetchAppDetail(ctx, app.ID)
		if err != nil {
			log.Errorf("Error fetching app detail for app ID %d: %v", app.ID, err)
			return nil, err
		}
		log.Infof("Successfully fetched app detail for app ID %d", app.ID)
		log.Infof("App detail for ID %d: %+v", app.ID, detail)

		for _, ar := range detail.AccessRequests {
			if ar.Status != "approved" || ar.WebhookURL == "" {
				continue
			}
			for _, cred := range ar.Credentials {
				webhookCredentials = append(webhookCredentials, WebhookCredential{
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

	return webhookCredentials, nil
}

func (c *portalClient) fetchApps(ctx context.Context, page int) ([]App, error) {
	url := fmt.Sprintf("%s/apps?page=%d&per_page=10", c.baseURL, page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", c.secret)
	req.Header.Set("Content-Type", applicationJSON)
	req.Header.Set("Accept", applicationJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apps []App
	if err := json.NewDecoder(resp.Body).Decode(&apps); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return apps, nil
}

func (c *portalClient) fetchAppDetail(ctx context.Context, appID int) (*AppDetail, error) {
	url := fmt.Sprintf("%s/apps/%d", c.baseURL, appID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", c.secret)
	req.Header.Set("Content-Type", applicationJSON)
	req.Header.Set("Accept", applicationJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	log.Printf("Raw response body: %s", string(bodyBytes))

	var detail AppDetail
	if err := json.Unmarshal(bodyBytes, &detail); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	log.Infof("App detail for ID %d: %+v", appID, detail)

	return &detail, nil
}

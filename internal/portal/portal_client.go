package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const applicationJSON = "application/json"

// Client is a client application for the portal API
type Client struct {
	Secret  string
	BaseURL string
}

// App represents the structure of an application from the developer portal
type App struct {
	ID          int    `json:"ID"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	UserID      int    `json:"UserID"`
	// Assuming other fields based on the provided example
}

// AppDetail includes detailed information about an application, including webhooks
type AppDetail struct {
	ID             int `json:"ID"`
	AccessRequests []struct {
		WebhookEventTypes string `json:"WebhookEventTypes"`
		WebhookSecret     string `json:"WebhookSecret"`
		WebhookURL        string `json:"WebhookURL"`
	} `json:"AccessRequests"`
	// Assuming other fields based on the provided example
}

// WebhookCredential contains the necessary fields to describe a webhook
type WebhookCredential struct {
	AppID             int
	AppName           string
	WebhookEventTypes string
	WebhookSecret     string
	WebhookURL        string
}

// NewClient creates a new Client for interacting with the portal API
func NewClient(baseURL, secret string) *Client {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	if !strings.HasSuffix(baseURL, "portal-api/") {
		baseURL += "portal-api/"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{Secret: secret, BaseURL: baseURL}
}

// ListWebhookCredentials retrieves a list of apps and filters out their webhook credentials
func (client *Client) ListWebhookCredentials() ([]WebhookCredential, error) {
	var allApps []App
	for page := 1; ; page++ {
		apps, err := client.fetchApps(page)
		if err != nil {
			return nil, err
		}

		allApps = append(allApps, apps...)

		if len(apps) < 10 {
			break
		}
	}

	var webhookCredentials []WebhookCredential
	for _, app := range allApps {
		detail, err := client.fetchAppDetail(app.ID)
		if err != nil {
			return nil, err
		}

		for _, ar := range detail.AccessRequests {
			if ar.WebhookURL != "" {
				webhookCredentials = append(webhookCredentials, WebhookCredential{
					AppID:             app.ID,
					AppName:           app.Name,
					WebhookEventTypes: ar.WebhookEventTypes,
					WebhookSecret:     ar.WebhookSecret,
					WebhookURL:        ar.WebhookURL,
				})
			}
		}
	}

	return webhookCredentials, nil
}

func (client *Client) fetchApps(page int) ([]App, error) {
	url := fmt.Sprintf("%s/apps?page=%d&per_page=10", client.BaseURL, page)

	ctx := context.Background()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", client.Secret)
	request.Header.Set("Content-Type", applicationJSON)
	request.Header.Set("Accept", applicationJSON)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch apps, status code: %d", resp.StatusCode)
	}

	var apps []App
	err = json.NewDecoder(resp.Body).Decode(&apps)
	if err != nil {
		return nil, err
	}

	return apps, nil
}

func (client *Client) fetchAppDetail(appID int) (*AppDetail, error) {
	url := fmt.Sprintf("%s/apps/%d", client.BaseURL, appID)

	ctx := context.Background()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", client.Secret)
	request.Header.Set("Content-Type", applicationJSON)
	request.Header.Set("Accept", applicationJSON)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch app detail, status code: %d", resp.StatusCode)
	}

	var detail AppDetail
	err = json.NewDecoder(resp.Body).Decode(&detail)
	if err != nil {
		return nil, err
	}

	return &detail, nil
}

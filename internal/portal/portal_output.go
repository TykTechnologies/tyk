package portal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	_ "github.com/warpstreamlabs/bento/public/components/pure"
	"github.com/warpstreamlabs/bento/public/service"
)

type portalOutputConfig struct {
	PortalURL string `json:"portal_url"`
	Secret    string `json:"secret"`
	EventType string `json:"event_type"`
	Headers   map[string]string
}

func newPortalOutputConfig() *portalOutputConfig {
	return &portalOutputConfig{}
}

type portalOutput struct {
	conf         *portalOutputConfig
	portalClient *Client
}

func newPortalOutput(conf *portalOutputConfig, _ *service.Resources) *portalOutput {
	client := NewClient(conf.PortalURL, conf.Secret)
	return &portalOutput{conf: conf, portalClient: client}
}

func (p *portalOutput) Connect(_ context.Context) error {
	log.Println("Connecting to Portal API")
	// Connection logic here if necessary, e.g., test connection or fetch token.
	// For simplicity, consider the portal client already prepared for requests.
	return nil
}

func (p *portalOutput) Write(_ context.Context, msg *service.Message) error {
	webhooks, err := p.portalClient.ListWebhookCredentials()
	if err != nil {
		return fmt.Errorf("failed to list webhook credentials: %w", err)
	}

	content, err := msg.AsBytes()
	if err != nil {
		return err
	}

	for _, webhook := range webhooks {
		if strings.Contains(webhook.WebhookEventTypes, p.conf.EventType) {
			go func(webhookURL string, content []byte) {
				if err := p.sendToWebhook(webhookURL, content); err != nil {
					log.Printf("failed to send event to webhook URL %s: %v", webhookURL, err)
				}
			}(webhook.WebhookURL, content)
		}
	}

	return nil
}

func (p *portalOutput) sendToWebhook(url string, data []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range p.conf.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode >= 300 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		return fmt.Errorf("received non-success code from webhook: %s, response: %s", resp.Status, string(respBody))
	}

	return nil
}

func (p *portalOutput) Close(_ context.Context) error {
	log.Println("Closing Portal Output")
	// Cleanup resources here if necessary
	return nil
}

func portalOutputConfigSpec() *service.ConfigSpec {
	spec := service.NewConfigSpec().
		Summary("Posts messages to dynamically fetched webhooks based on event type.").
		Description("This output plugin fetches webhooks based on a specified event type and posts messages to them.").
		Field(service.NewStringField("portal_url").Description("The API URL of the Portal.")).
		Field(service.NewStringField("secret").Description("The secret key for accessing the API.")).
		Field(service.NewStringField("event_type").Description("The event type to filter the webhooks by.")).
		Field(service.NewStringMapField("headers").Description("Headers to add to the request."))

	return spec
}

func init() {
	err := service.RegisterOutput("portal_webhook", portalOutputConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Output, int, error) {
			config := newPortalOutputConfig()
			var err error
			config.EventType, err = conf.FieldString("event_type")
			if err != nil {
				return nil, 0, err
			}
			config.Secret, err = conf.FieldString("secret")
			if err != nil {
				return nil, 0, err
			}
			config.PortalURL, err = conf.FieldString("portal_url")
			if err != nil {
				return nil, 0, err
			}
			config.Headers, err = conf.FieldStringMap("headers")
			if err != nil {
				return nil, 0, err
			}

			return newPortalOutput(config, mgr), 1, nil
		},
	)

	if err != nil {
		panic(err)
	}
}

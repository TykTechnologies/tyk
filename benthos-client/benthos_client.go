package benthosClient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client
}

func NewClient(baseURL, username, password string) *Client {
	return &Client{
		BaseURL:    baseURL,
		Username:   username,
		Password:   password,
		HTTPClient: &http.Client{},
	}
}

func (c *Client) newRequest(method, path string, body []byte) (*http.Request, error) {
	fullPath := fmt.Sprintf("%s%s", c.BaseURL, path)
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, fullPath, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, fullPath, nil)
	}
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	return req, nil
}

func (c *Client) doRequest(req *http.Request) (map[string]interface{}, error) {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error reading response: ", err)
		return nil, err
	}

	// try to decode JSON
	var o interface{}
	output := make(map[string]interface{})
	err = json.Unmarshal(b, &output)
	o = output
	if err != nil {
		o = string(b)
	}

	result = make(map[string]interface{})
	result["status"] = resp.StatusCode
	result["body"] = o

	return result, nil
}

func (c *Client) GetReady() (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodGet, "/ready", nil)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *Client) GetStreams() (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodGet, "/streams", nil)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *Client) CreateStream(streamID string, config []byte) (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodPost, fmt.Sprintf("/streams/%s", streamID), config)
	if err != nil {
		return nil, err
	}

	return c.doRequest(req)
}

func (c *Client) GetStream(streamID string) (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodGet, fmt.Sprintf("/streams/%s", streamID), nil)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *Client) UpdateStream(streamID string, config []byte) (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodPatch, fmt.Sprintf("/streams/%s", streamID), config)
	if err != nil {
		return nil, err
	}

	return c.doRequest(req)
}

func (c *Client) PatchStream(streamID string, config []byte) (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodPatch, fmt.Sprintf("/streams/%s", streamID), config)
	if err != nil {
		return nil, err
	}

	return c.doRequest(req)
}

func (c *Client) DeleteStream(streamID string) (map[string]interface{}, error) {
	req, err := c.newRequest(http.MethodDelete, fmt.Sprintf("/streams/%s", streamID), nil)
	if err != nil {
		return nil, err
	}

	return c.doRequest(req)
}

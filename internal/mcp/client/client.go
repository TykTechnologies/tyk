package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
)

const (
	protocolVersion      = "2025-03-26"
	clientName           = "tyk-gateway"
	clientVersion        = "1.0.0"
	maxPrimitivesPerType = 10000
	maxPrimitiveNameLen  = 256
	sessionHeader        = "Mcp-Session-Id"
)

var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-\./:*@]+$`)

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"` // nil for notifications
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Option configures the Client.
type Option func(*Client)

// WithHTTPClient sets a custom *http.Client for the introspection client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// Client is a minimal MCP introspection client that discovers server
// capabilities via the JSON-RPC based MCP protocol.
type Client struct {
	httpClient *http.Client
	idCounter  atomic.Int64
}

// New creates a new introspection Client with the given options.
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Client) nextID() int64 {
	return c.idCounter.Add(1)
}

// Introspect performs the full MCP handshake and capability discovery against
// the given upstream URL. It returns the discovered capabilities along with
// any partial errors encountered during list operations.
func (c *Client) Introspect(ctx context.Context, upstreamURL string) (*IntrospectionResult, error) {
	// Step 1: Initialize handshake.
	sessionID, serverInfo, err := c.initialize(ctx, upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("mcp initialize: %w", err)
	}

	// Step 2: Send initialized notification.
	if err := c.sendInitialized(ctx, upstreamURL, sessionID); err != nil {
		return nil, fmt.Errorf("mcp initialized notification: %w", err)
	}

	// Step 3: Discover capabilities.
	result := &IntrospectionResult{
		Capabilities: &ServerCapabilities{
			ServerInfo: serverInfo,
		},
	}

	tools, err := c.listAll(ctx, upstreamURL, sessionID, "tools/list", "tools")
	if err != nil {
		result.Errors = append(result.Errors, IntrospectionError{Method: "tools/list", Err: err.Error()})
		result.Partial = true
	} else {
		result.Capabilities.Tools = parseTools(tools)
	}

	resources, err := c.listAll(ctx, upstreamURL, sessionID, "resources/list", "resources")
	if err != nil {
		result.Errors = append(result.Errors, IntrospectionError{Method: "resources/list", Err: err.Error()})
		result.Partial = true
	} else {
		result.Capabilities.Resources = parseResources(resources)
	}

	prompts, err := c.listAll(ctx, upstreamURL, sessionID, "prompts/list", "prompts")
	if err != nil {
		result.Errors = append(result.Errors, IntrospectionError{Method: "prompts/list", Err: err.Error()})
		result.Partial = true
	} else {
		result.Capabilities.Prompts = parsePrompts(prompts)
	}

	return result, nil
}

// initialize sends the JSON-RPC initialize request and returns the session ID
// and server info.
func (c *Client) initialize(ctx context.Context, url string) (string, ServerInfo, error) {
	id := c.nextID()
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    clientName,
				"version": clientVersion,
			},
		},
	}

	resp, httpResp, err := c.doRPC(ctx, url, "", req)
	if err != nil {
		return "", ServerInfo{}, err
	}

	if resp.Error != nil {
		return "", ServerInfo{}, fmt.Errorf("server error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	// Extract session ID from response header.
	sessionID := httpResp.Header.Get(sessionHeader)

	// Parse server info from the result.
	var initResult struct {
		ServerInfo ServerInfo `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &initResult); err != nil {
		return "", ServerInfo{}, fmt.Errorf("parse initialize result: %w", err)
	}

	return sessionID, initResult.ServerInfo, nil
}

// sendInitialized sends the notifications/initialized notification.
func (c *Client) sendInitialized(ctx context.Context, url, sessionID string) error {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		httpReq.Header.Set(sessionHeader, sessionID)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain body so the connection can be reused.
	io.Copy(io.Discard, resp.Body)

	return nil
}

// listAll performs paginated listing of a primitive type, accumulating results
// across pages.
func (c *Client) listAll(ctx context.Context, url, sessionID, method, key string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	var cursor string

	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		id := c.nextID()
		req := jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      &id,
			Method:  method,
			Params:  params,
		}

		resp, _, err := c.doRPC(ctx, url, sessionID, req)
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("server error %d: %s", resp.Error.Code, resp.Error.Message)
		}

		var page map[string]json.RawMessage
		if err := json.Unmarshal(resp.Result, &page); err != nil {
			return nil, fmt.Errorf("parse %s result: %w", method, err)
		}

		if items, ok := page[key]; ok {
			var arr []json.RawMessage
			if err := json.Unmarshal(items, &arr); err != nil {
				return nil, fmt.Errorf("parse %s items: %w", key, err)
			}
			all = append(all, arr...)
		}

		if len(all) > maxPrimitivesPerType {
			all = all[:maxPrimitivesPerType]
			return all, nil
		}

		var nextCursor string
		if raw, ok := page["nextCursor"]; ok {
			json.Unmarshal(raw, &nextCursor)
		}
		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}

	return all, nil
}

// doRPC sends a JSON-RPC request over HTTP and returns the parsed response.
// It handles both application/json and text/event-stream response content types.
func (c *Client) doRPC(ctx context.Context, url, sessionID string, req jsonRPCRequest) (*jsonRPCResponse, *http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		httpReq.Header.Set(sessionHeader, sessionID)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return nil, nil, fmt.Errorf("unexpected status %d: %s", httpResp.StatusCode, string(respBody))
	}

	ct := httpResp.Header.Get("Content-Type")

	var rpcResp jsonRPCResponse

	if strings.HasPrefix(ct, "text/event-stream") {
		raw, err := extractSSEData(httpResp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("parse SSE response: %w", err)
		}
		if err := json.Unmarshal(raw, &rpcResp); err != nil {
			return nil, nil, fmt.Errorf("unmarshal SSE JSON-RPC response: %w", err)
		}
	} else {
		if err := json.NewDecoder(httpResp.Body).Decode(&rpcResp); err != nil {
			return nil, nil, fmt.Errorf("decode JSON-RPC response: %w", err)
		}
	}

	return &rpcResp, httpResp, nil
}

// extractSSEData reads an SSE stream and returns the data payload from the
// first "message" event.
func extractSSEData(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	var eventType string
	var dataParts []string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line dispatches the event.
			if (eventType == "message" || eventType == "") && len(dataParts) > 0 {
				return []byte(strings.Join(dataParts, "\n")), nil
			}
			// Reset for the next event.
			eventType = ""
			dataParts = nil
			continue
		}

		if val, ok := strings.CutPrefix(line, "event:"); ok {
			eventType = strings.TrimSpace(val)
		} else if val, ok := strings.CutPrefix(line, "data:"); ok {
			dataParts = append(dataParts, strings.TrimSpace(val))
		}
	}

	// Handle case where stream ends without trailing blank line.
	if (eventType == "message" || eventType == "") && len(dataParts) > 0 {
		return []byte(strings.Join(dataParts, "\n")), nil
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("no message event found in SSE stream")
}

// validateName checks that a primitive name matches the allowed pattern.
func validateName(name string) bool {
	if len(name) == 0 || len(name) > maxPrimitiveNameLen {
		return false
	}
	return validNameRe.MatchString(name)
}

func parseTools(raw []json.RawMessage) []ToolInfo {
	var tools []ToolInfo
	for _, r := range raw {
		var t ToolInfo
		if err := json.Unmarshal(r, &t); err != nil {
			continue
		}
		if !validateName(t.Name) {
			continue
		}
		tools = append(tools, t)
	}
	return tools
}

func parseResources(raw []json.RawMessage) []ResourceInfo {
	var resources []ResourceInfo
	for _, r := range raw {
		var ri ResourceInfo
		if err := json.Unmarshal(r, &ri); err != nil {
			continue
		}
		if !validateName(ri.Name) {
			continue
		}
		resources = append(resources, ri)
	}
	return resources
}

func parsePrompts(raw []json.RawMessage) []PromptInfo {
	var prompts []PromptInfo
	for _, r := range raw {
		var p PromptInfo
		if err := json.Unmarshal(r, &p); err != nil {
			continue
		}
		if !validateName(p.Name) {
			continue
		}
		prompts = append(prompts, p)
	}
	return prompts
}

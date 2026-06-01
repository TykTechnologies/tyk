package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"

	sdkjsonrpc "github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// SDKAdapter owns one long-lived SDK server and its current derived tool set.
// Updating the tool set mutates the server in place; list-change notifications
// are intentionally not advertised for REST-as-MCP adapters.
type SDKAdapter struct {
	server   *mcpsdk.Server
	callTool ToolCallFunc
	handler  http.Handler

	mu    sync.RWMutex
	tools map[string]oas.DerivedTool
}

// ToolCallFunc executes one derived MCP tool and returns the captured REST
// response. Gateway code supplies the implementation that loops through the
// paired REST API chain.
type ToolCallFunc func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error)

// SDKServerConfig describes an SDK-backed MCP server for a derived REST API.
type SDKServerConfig struct {
	// Name is advertised as serverInfo.name during MCP initialize.
	Name string
	// Version is advertised as serverInfo.version. Defaults to "1.0".
	Version string
	// Tools is the load-time OAS-derived tool catalogue.
	Tools []oas.DerivedTool
	// CallTool executes a tools/call against the paired REST API.
	CallTool ToolCallFunc
}

// NewSDKServer builds an official Go MCP SDK server from the derived tool
// catalogue. Tool list changes are intentionally advertised as static for this
// adapter: a changed REST OAS is picked up by gateway reload/reconnect, not by
// live notifications.
func NewSDKServer(config SDKServerConfig) (*mcpsdk.Server, error) {
	return newSDKServer(config, false)
}

// NewSDKAdapter builds a stateful SDK-backed adapter. Its server does not
// advertise tools/list_changed; clients discover catalogue changes by reload or
// reconnect.
func NewSDKAdapter(config SDKServerConfig) (*SDKAdapter, error) {
	server, err := newSDKServer(SDKServerConfig{
		Name:     config.Name,
		Version:  config.Version,
		CallTool: config.CallTool,
	}, false)
	if err != nil {
		return nil, err
	}

	adapter := &SDKAdapter{
		server:   server,
		callTool: config.CallTool,
		tools:    map[string]oas.DerivedTool{},
	}
	adapter.handler = adapter.newStreamableHTTPHandler(defaultSDKAdapterStreamableHTTPOptions())
	if err := adapter.UpdateTools(config.Tools); err != nil {
		return nil, err
	}
	return adapter, nil
}

// Server returns the underlying SDK server. Callers should use UpdateTools
// rather than mutating tools on the server directly.
func (a *SDKAdapter) Server() *mcpsdk.Server {
	if a == nil {
		return nil
	}
	return a.server
}

// UpdateCallTool replaces the gateway callback used by tool handlers. This is
// needed when a long-lived SDK adapter is reused across gateway reloads and the
// adapter spec pointer has changed.
func (a *SDKAdapter) UpdateCallTool(callTool ToolCallFunc) error {
	if a == nil {
		return fmt.Errorf("nil SDK adapter")
	}
	if callTool == nil {
		return fmt.Errorf("adapter SDK server requires CallTool")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.callTool = callTool
	return nil
}

// StreamableHTTPHandler returns a streamable HTTP handler backed by the
// adapter's long-lived SDK server. Nil options return the adapter-owned,
// stateful handler so initialized streamable sessions survive across gateway
// requests. Non-nil options intentionally build a separate handler.
func (a *SDKAdapter) StreamableHTTPHandler(opts *mcpsdk.StreamableHTTPOptions) http.Handler {
	if opts == nil {
		return a.handler
	}
	return a.newStreamableHTTPHandler(opts)
}

func (a *SDKAdapter) newStreamableHTTPHandler(opts *mcpsdk.StreamableHTTPOptions) http.Handler {
	return mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return a.Server()
	}, opts)
}

func defaultSDKAdapterStreamableHTTPOptions() *mcpsdk.StreamableHTTPOptions {
	return &mcpsdk.StreamableHTTPOptions{
		JSONResponse: true,
	}
}

// UpdateTools replaces the adapter's derived tool catalogue in place. Added,
// removed, and changed tools are applied through the SDK server; capabilities
// keep list-change notifications disabled.
func (a *SDKAdapter) UpdateTools(tools []oas.DerivedTool) error {
	if a == nil || a.server == nil {
		return fmt.Errorf("nil SDK adapter")
	}

	next := make(map[string]oas.DerivedTool, len(tools))
	for _, tool := range tools {
		if err := ValidateToolMetadata(&tool); err != nil {
			return err
		}
		next[tool.Name] = tool
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	var remove []string
	for name := range a.tools {
		if _, ok := next[name]; !ok {
			remove = append(remove, name)
		}
	}
	sort.Strings(remove)

	for _, name := range remove {
		a.server.RemoveTools(name)
		delete(a.tools, name)
	}

	for _, tool := range tools {
		current, ok := a.tools[tool.Name]
		if ok && reflect.DeepEqual(current, tool) {
			continue
		}
		a.addTool(tool)
		a.tools[tool.Name] = tool
	}

	return nil
}

func newSDKServer(config SDKServerConfig, listChanged bool) (*mcpsdk.Server, error) {
	if config.CallTool == nil {
		return nil, fmt.Errorf("adapter SDK server requires CallTool")
	}

	version := config.Version
	if version == "" {
		version = "1.0"
	}

	server := mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: config.Name, Version: version},
		&mcpsdk.ServerOptions{
			Capabilities: &mcpsdk.ServerCapabilities{
				Tools: &mcpsdk.ToolCapabilities{ListChanged: listChanged},
			},
		},
	)

	adapter := &SDKAdapter{
		server:   server,
		callTool: config.CallTool,
		tools:    map[string]oas.DerivedTool{},
	}
	for i := range config.Tools {
		tool := config.Tools[i]
		if err := ValidateToolMetadata(&tool); err != nil {
			return nil, err
		}
		adapter.addTool(tool)
	}

	return server, nil
}

func (a *SDKAdapter) addTool(tool oas.DerivedTool) {
	a.server.AddTool(&mcpsdk.Tool{
		Name:        tool.Name,
		Description: tool.Description,
		InputSchema: toolInputSchema(tool.InputSchema),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		args, err := unmarshalToolArgs(req)
		if err != nil {
			return nil, err
		}

		rec, err := a.callToolForRequest(ctx, &tool, args)
		if err != nil {
			if IsInvalidParams(err) {
				return nil, &sdkjsonrpc.Error{Code: sdkjsonrpc.CodeInvalidParams, Message: err.Error()}
			}
			return nil, err
		}
		if rec == nil {
			return nil, fmt.Errorf("tool %q returned nil recorder", tool.Name)
		}

		return SDKToolResult(rec), nil
	})
}

func (a *SDKAdapter) callToolForRequest(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*Recorder, error) {
	a.mu.RLock()
	callTool := a.callTool
	a.mu.RUnlock()

	if callTool == nil {
		return nil, fmt.Errorf("adapter SDK server requires CallTool")
	}
	return callTool(ctx, tool, args)
}

// NewSDKStreamableHTTPHandler builds an SDK streamable HTTP handler for the
// adapter server. Nil options default to stateless JSON responses, matching the
// current single-request adapter semantics.
func NewSDKStreamableHTTPHandler(config SDKServerConfig, opts *mcpsdk.StreamableHTTPOptions) (http.Handler, error) {
	server, err := NewSDKServer(config)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &mcpsdk.StreamableHTTPOptions{
			Stateless:    true,
			JSONResponse: true,
		}
	}
	return mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return server
	}, opts), nil
}

// SDKToolResult maps a captured REST response to the SDK's CallToolResult
// shape while preserving the envelope semantics used by ToolResultEnvelope.
func SDKToolResult(rec *Recorder) *mcpsdk.CallToolResult {
	meta := mcpsdk.Meta{
		"upstreamHttpStatus":  rec.Status(),
		"upstreamContentType": rec.ContentType(),
	}
	if rec.Truncated() {
		meta["truncated"] = true
	}

	return &mcpsdk.CallToolResult{
		Meta: meta,
		Content: []mcpsdk.Content{
			&mcpsdk.TextContent{Text: ToolResultText(rec)},
		},
		IsError: rec.Status() >= 400,
	}
}

func unmarshalToolArgs(req *mcpsdk.CallToolRequest) (map[string]any, error) {
	args := map[string]any{}
	if req == nil || req.Params == nil || len(req.Params.Arguments) == 0 {
		return args, nil
	}
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return nil, fmt.Errorf("invalid tools/call arguments: %w", err)
	}
	return args, nil
}

func toolInputSchema(schema map[string]any) any {
	if schema == nil {
		return map[string]any{"type": "object"}
	}
	return schema
}

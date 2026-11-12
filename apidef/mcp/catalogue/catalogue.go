// Package catalogue lists the tools of a remote MCP server, for checking
// x-tyk-mcp-server tool overrides against the upstream catalogue with
// oas.CheckRemoteMCPToolCatalogue.
package catalogue

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	protocolVersion     = "2025-06-18"
	maxPages            = 1000
	maxBodyBytes        = 10 << 20
	sessionCloseTimeout = 2 * time.Second
)

// FetchToolNames lists every tool name an MCP server exposes over
// Streamable HTTP: initialize, notifications/initialized, then tools/list
// following nextCursor until the last page, then a best-effort session DELETE.
// JSON and text/event-stream responses are accepted.
//
// header is sent on every request (for example upstream credentials).
// Redirects are never followed, whatever the client's policy, so header
// cannot reach another host; a 3xx response is an error. The caller bounds
// the call through ctx and the client's timeout.
func FetchToolNames(ctx context.Context, client *http.Client, url string, header http.Header) ([]string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &session{client: &noRedirects, url: url, header: header}

	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := s.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "tyk-gateway", "version": "1"},
	}, &initResult); err != nil {
		return nil, err
	}
	s.protocolVersion = initResult.ProtocolVersion
	if s.protocolVersion == "" {
		s.protocolVersion = protocolVersion
	}
	defer s.close()

	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		return nil, err
	}

	var names []string
	seenCursors := map[string]struct{}{}
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := s.call(ctx, "tools/list", params, &result); err != nil {
			return nil, err
		}
		for _, tool := range result.Tools {
			names = append(names, tool.Name)
		}
		if result.NextCursor == "" {
			return names, nil
		}
		if _, repeated := seenCursors[result.NextCursor]; repeated {
			return nil, fmt.Errorf("tools/list returned repeated cursor %q", result.NextCursor)
		}
		seenCursors[result.NextCursor] = struct{}{}
		cursor = result.NextCursor
	}
	return nil, fmt.Errorf("tools/list exceeded %d pages", maxPages)
}

type session struct {
	client          *http.Client
	url             string
	header          http.Header
	protocolVersion string
	sessionID       string
	nextID          int
}

func (s *session) newRequest(ctx context.Context, method string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, values := range s.header {
		req.Header[name] = append([]string(nil), values...)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.protocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", s.protocolVersion)
	}
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	return req, nil
}

func (s *session) call(ctx context.Context, method string, params any, out any) error {
	s.nextID++
	id := s.nextID
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := s.newRequest(ctx, http.MethodPost, body)
	if err != nil {
		return err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("%s: upstream returned status %d", method, res.StatusCode)
	}
	if sessionID := res.Header.Get("Mcp-Session-Id"); sessionID != "" {
		s.sessionID = sessionID
	}

	raw, err := readResponse(res, id)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: invalid JSON-RPC response: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: upstream error %d: %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return fmt.Errorf("%s: invalid result: %w", method, err)
	}
	return nil
}

func (s *session) notify(ctx context.Context, method string) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	req, err := s.newRequest(ctx, http.MethodPost, body)
	if err != nil {
		return err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	_, drainErr := io.Copy(io.Discard, io.LimitReader(res.Body, maxBodyBytes))
	_ = res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("%s: upstream returned status %d", method, res.StatusCode)
	}
	if drainErr != nil {
		return fmt.Errorf("%s: reading response: %w", method, drainErr)
	}
	return nil
}

func (s *session) close() {
	if s.sessionID == "" {
		return
	}
	// Session teardown is courtesy only; a fresh context lets it run even
	// after the caller's deadline has fired.
	ctx, cancel := context.WithTimeout(context.Background(), sessionCloseTimeout)
	defer cancel()
	req, err := s.newRequest(ctx, http.MethodDelete, nil)
	if err != nil {
		return
	}
	if res, err := s.client.Do(req); err == nil {
		_ = res.Body.Close()
	}
}

// readResponse returns the JSON-RPC response for id from either a
// JSON body or the first matching message event of an SSE stream.
func readResponse(res *http.Response, id int) ([]byte, error) {
	body := io.LimitReader(res.Body, maxBodyBytes)
	// A missing or unparsable Content-Type is read as a plain JSON body; the
	// JSON-RPC decoding that follows reports anything that is not one. A
	// malformed parameter still yields the media type, so an event stream
	// with, say, a bare "charset" is parsed as one.
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if (err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter)) || mediaType != "text/event-stream" {
		return io.ReadAll(body)
	}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64<<10), maxBodyBytes)
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if raw, ok := matchingEvent(data, id); ok {
				return raw, nil
			}
			data = data[:0]
			continue
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	if raw, ok := matchingEvent(data, id); ok {
		return raw, nil
	}
	return nil, errors.New("event stream ended without a response")
}

func matchingEvent(data []string, id int) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	raw := []byte(strings.Join(data, "\n"))
	var probe struct {
		ID json.Number `json:"id"`
	}
	if json.Unmarshal(raw, &probe) != nil || probe.ID.String() != fmt.Sprint(id) {
		return nil, false
	}
	return raw, true
}

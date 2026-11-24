package gateway

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/mcp/tooloverride"
)

var (
	errUnsupportedContentEncoding = errors.New("unsupported Content-Encoding")
	errDecodedBodyTooLarge        = errors.New("decoded response body exceeds the maximum response body size")
)

// mcpDecodedResponseBodyLimit bounds a decoded MCP response body when
// max_response_body_size is not set, so a small compressed body cannot
// expand without limit in memory.
const mcpDecodedResponseBodyLimit int64 = 32 << 20

// mcpDecodeLimit returns the decoded-size bound for MCP response bodies:
// the configured maximum response body size, or mcpDecodedResponseBodyLimit.
func mcpDecodeLimit(configured int64) int64 {
	if configured > 0 {
		return configured
	}
	return mcpDecodedResponseBodyLimit
}

// mcpResponseWarningInterval is how often the same MCP response warning is
// logged for one API, so per-request failures cannot flood the log.
const mcpResponseWarningInterval = tooloverride.MissingSourceWarningInterval

// mcpResponseContentEncoding returns the normalised Content-Encoding of an
// upstream MCP response, or "" when the body is not encoded.
func mcpResponseContentEncoding(h http.Header) string {
	encoding := strings.ToLower(strings.TrimSpace(h.Get(header.ContentEncoding)))
	if encoding == "identity" {
		return ""
	}
	return encoding
}

// newContentDecoder returns a reader that decodes r from encoding. gzip and
// deflate are supported; deflate accepts both the zlib format RFC 9110
// specifies and the raw format some servers send.
func newContentDecoder(encoding string, r io.Reader) (io.Reader, error) {
	switch encoding {
	case "gzip", "x-gzip":
		return gzip.NewReader(r)
	case "deflate":
		buffered := bufio.NewReader(r)
		if prefix, err := buffered.Peek(2); err == nil && isZlibHeader(prefix) {
			return zlib.NewReader(buffered)
		}
		return flate.NewReader(buffered), nil
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedContentEncoding, encoding)
	}
}

func isZlibHeader(b []byte) bool {
	return b[0]&0x0f == 8 && (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}

// decodeMCPResponseBody decodes a complete upstream response body. limit
// bounds the decoded size when positive.
func decodeMCPResponseBody(encoding string, raw []byte, limit int64) ([]byte, error) {
	if encoding == "" || encoding == "identity" {
		return raw, nil
	}
	decoder, err := newContentDecoder(encoding, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if limit > 0 {
		decoder = io.LimitReader(decoder, limit+1)
	}
	decoded, err := io.ReadAll(decoder)
	if err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(decoded)) > limit {
		return nil, errDecodedBodyTooLarge
	}
	return decoded, nil
}

// decodingReadCloser decodes a streamed body. The decoder is created on the
// first Read, so wrapping a response never blocks on the upstream. The
// decoder is read through a bufio.Reader, whose Read makes at most one read
// of the decoder, so streamed events are not held back.
type decodingReadCloser struct {
	src      io.ReadCloser
	encoding string
	decoded  *bufio.Reader
	err      error
}

func (d *decodingReadCloser) Read(p []byte) (int, error) {
	if d.decoded == nil && d.err == nil {
		var decoder io.Reader
		if decoder, d.err = newContentDecoder(d.encoding, d.src); d.err == nil {
			d.decoded = bufio.NewReader(decoder)
		}
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.decoded.Read(p)
}

// Close closes the upstream body only; it may be called while a Read is
// blocked, and closing the source is what unblocks it.
func (d *decodingReadCloser) Close() error {
	return d.src.Close()
}

// mcpDecodableAcceptEncodings are the content codings the Gateway can decode.
var mcpDecodableAcceptEncodings = map[string]bool{"gzip": true, "x-gzip": true, "deflate": true, "identity": true}

// restrictMCPAcceptEncoding keeps only the codings the Gateway can decode in
// an outbound Accept-Encoding, so an upstream never answers a response the
// Gateway must rewrite or filter with br, zstd or another coding it cannot
// read. Quality values are kept. When nothing decodable is left, it asks for
// identity. An absent header stays absent.
func restrictMCPAcceptEncoding(h http.Header) {
	values := h.Values(header.AcceptEncoding)
	if len(values) == 0 {
		return
	}
	var kept []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			coding := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
			if mcpDecodableAcceptEncodings[coding] {
				kept = append(kept, part)
			}
		}
	}
	if len(kept) == 0 {
		kept = []string{"identity"}
	}
	h.Set(header.AcceptEncoding, strings.Join(kept, ", "))
}

// mcpResponseMayBeEdited reports whether the Gateway may rewrite or filter
// the response to an MCP request: list methods, initialize, discovery, and
// GET event streams, which carry list responses too.
func mcpResponseMayBeEdited(r *http.Request) bool {
	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil {
		return r.Method == http.MethodGet
	}
	switch state.Method {
	case mcp.MethodToolsList, mcp.MethodPromptsList, mcp.MethodResourcesList, mcp.MethodResourcesTemplatesList,
		mcp.MethodInitialize, mcp.MethodServerDiscover:
		return true
	}
	return false
}

// decodeMCPEventStream makes a compressed upstream event stream readable by
// the SSE hooks: a supported encoding is decoded and the stream is sent to
// the client decoded. An unsupported one is left alone with a warning.
func decodeMCPEventStream(spec *APISpec, res *http.Response, logger *logrus.Entry) {
	encoding := mcpResponseContentEncoding(res.Header)
	if encoding == "" {
		return
	}
	if _, err := newContentDecoder(encoding, bytes.NewReader(nil)); errors.Is(err, errUnsupportedContentEncoding) {
		warnMCPResponseEncoding(spec, encoding, err, logger)
		return
	}
	res.Body = &decodingReadCloser{src: res.Body, encoding: encoding}
	res.Header.Del(header.ContentEncoding)
	res.Header.Del(header.ContentLength)
	res.ContentLength = -1
}

func warnMCPResponseEncoding(spec *APISpec, encoding string, err error, logger *logrus.Entry) {
	if !spec.mcpResponseWarnings.due("encoding:"+encoding, time.Now()) {
		return
	}
	logger.WithFields(logrus.Fields{"api_id": spec.APIID, "content_encoding": encoding}).WithError(err).
		Warning("Upstream MCP response could not be decoded; MCP tool overrides and access rules were not applied to it")
}

// mcpWarningLimiter lets one warning per key through per
// mcpResponseWarningInterval.
type mcpWarningLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *mcpWarningLimiter) due(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.last[key]; ok && now.Sub(last) < mcpResponseWarningInterval {
		return false
	}
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	l.last[key] = now
	return true
}

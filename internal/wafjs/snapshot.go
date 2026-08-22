package wafjs

import (
	"bytes"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/dop251/goja"
)

// RequestSnapshot is the curated, read-only view of one inbound request
// handed to the engine. It never carries *http.Request, directly or by
// reference.
type RequestSnapshot struct {
	// Method is the request method, for example "GET".
	Method string
	// Scheme is the request scheme, for example "https".
	Scheme string
	// Host is the request host.
	Host string
	// RequestURI is the undecoded request-target, path plus query.
	RequestURI string
	// Path is the decoded URL path.
	Path string
	// Proto is the wire protocol, for example "HTTP/1.1".
	Proto string
	// Headers holds the inbound headers.
	Headers map[string][]string
	// Query holds the parsed query parameters.
	Query url.Values
	// Cookies holds the parsed cookies.
	Cookies []*http.Cookie
	// Body holds at most the configured number of wire bytes.
	Body []byte
	// BodyTruncated reports that the wire body exceeded the configured limit.
	BodyTruncated bool
}

// SnapshotRequest materialises a curated snapshot from r and restores r.Body
// for downstream readers. It reads at most maxBodyBytes plus one byte. The
// original body is closed exactly once, either immediately for a complete body
// or when the restored over-limit body is closed.
func SnapshotRequest(r *http.Request, maxBodyBytes int64) (RequestSnapshot, error) {
	if r == nil {
		return RequestSnapshot{}, newFailure(FailureKindSnapshot, "", "request_nil", nil)
	}
	if r.URL == nil {
		return RequestSnapshot{}, newFailure(FailureKindSnapshot, "", "url_missing", nil)
	}
	if maxBodyBytes < 0 || maxBodyBytes == math.MaxInt64 {
		return RequestSnapshot{}, newFailure(FailureKindBody, "", "limit_invalid", nil)
	}

	body, truncated, f := snapshotBody(r, maxBodyBytes)
	if f != nil {
		return RequestSnapshot{}, f
	}

	scheme := "http"
	if r.TLS != nil || r.URL.Scheme == "https" {
		scheme = "https"
	}
	requestURI := r.URL.RequestURI()
	if r.RequestURI != "" {
		requestURI = r.RequestURI
	}

	cookies := r.Cookies()
	cookieCopies := make([]*http.Cookie, len(cookies))
	for i, cookie := range cookies {
		clone := *cookie
		cookieCopies[i] = &clone
	}

	return RequestSnapshot{
		Method:        r.Method,
		Scheme:        scheme,
		Host:          r.Host,
		RequestURI:    requestURI,
		Path:          r.URL.Path,
		Proto:         r.Proto,
		Headers:       r.Header.Clone(),
		Query:         r.URL.Query(),
		Cookies:       cookieCopies,
		Body:          body,
		BodyTruncated: truncated,
	}, nil
}

func snapshotBody(r *http.Request, maxBodyBytes int64) ([]byte, bool, *Failure) {
	if r.Body == nil {
		return nil, false, nil
	}

	original := r.Body
	contentLength := r.ContentLength
	consumed, err := io.ReadAll(io.LimitReader(original, maxBodyBytes+1))
	r.ContentLength = contentLength
	if err != nil {
		r.Body = newRestoredBody(consumed, original)
		return nil, false, newFailure(FailureKindBody, "", "read", err)
	}

	if int64(len(consumed)) > maxBodyBytes {
		r.Body = newRestoredBody(consumed, original)
		return consumed[:maxBodyBytes], true, nil
	}

	r.Body = io.NopCloser(bytes.NewReader(consumed))
	if err := original.Close(); err != nil {
		return nil, false, newFailure(FailureKindBody, "", "close", err)
	}
	return consumed, false, nil
}

type restoredBody struct {
	io.Reader
	closer io.Closer
	once   sync.Once
	err    error
}

func newRestoredBody(prefix []byte, unread io.ReadCloser) *restoredBody {
	return &restoredBody{
		Reader: io.MultiReader(bytes.NewReader(prefix), unread),
		closer: unread,
	}
}

func (b *restoredBody) Close() error {
	b.once.Do(func() {
		b.err = b.closer.Close()
	})
	return b.err
}

// validate rejects structurally invalid snapshots.
func (s RequestSnapshot) validate() *Failure {
	if s.Method == "" {
		return newFailure(FailureKindSnapshot, "", "method_missing", nil)
	}
	if s.Path == "" {
		return newFailure(FailureKindSnapshot, "", "path_missing", nil)
	}
	return nil
}

// toJS binds the snapshot into a fresh JavaScript object. Every exposed
// collection is copied into engine-owned memory, so mutations inside the
// engine can never reach the caller's snapshot.
func (s RequestSnapshot) toJS(vm *goja.Runtime) (*goja.Object, *Failure) {
	o := vm.NewObject()
	bind := func(err error) *Failure {
		return newFailure(FailureKindInternal, "", "snapshot_binding", err)
	}

	if err := o.Set("method", s.Method); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("scheme", s.Scheme); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("host", s.Host); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("request_uri", s.RequestURI); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("path", s.Path); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("proto", s.Proto); err != nil {
		return nil, bind(err)
	}

	bodyBytes := slices.Clone(s.Body)
	buffer := vm.NewArrayBuffer(bodyBytes)
	uint8Array, ok := goja.AssertConstructor(vm.Get("Uint8Array"))
	if !ok {
		return nil, bind(newFailure(FailureKindInternal, "", "uint8array_unavailable", nil))
	}
	body, err := uint8Array(nil, vm.ToValue(buffer))
	if err != nil {
		return nil, bind(err)
	}
	if err := o.Set("body", body); err != nil {
		return nil, bind(err)
	}
	if err := o.Set("body_truncated", s.BodyTruncated); err != nil {
		return nil, bind(err)
	}

	headers, err := multiMapToJS(vm, s.Headers)
	if err != nil {
		return nil, bind(err)
	}
	if err := o.Set("headers", headers); err != nil {
		return nil, bind(err)
	}

	query, err := multiMapToJS(vm, s.Query)
	if err != nil {
		return nil, bind(err)
	}
	if err := o.Set("query", query); err != nil {
		return nil, bind(err)
	}

	var cookieValues []any
	for _, c := range s.Cookies {
		pair := vm.NewObject()
		if err := pair.Set("name", c.Name); err != nil {
			return nil, bind(err)
		}
		if err := pair.Set("value", c.Value); err != nil {
			return nil, bind(err)
		}
		cookieValues = append(cookieValues, pair)
	}
	if err := o.Set("cookies", vm.NewArray(cookieValues...)); err != nil {
		return nil, bind(err)
	}
	return o, nil
}

// multiMapToJS copies a multi-value map into a fresh JavaScript object of
// arrays with deterministic key order.
func multiMapToJS(vm *goja.Runtime, m map[string][]string) (*goja.Object, error) {
	o := vm.NewObject()
	for _, k := range slices.Sorted(maps.Keys(m)) {
		values := make([]any, len(m[k]))
		for i, v := range m[k] {
			values[i] = v
		}
		if err := o.Set(k, vm.NewArray(values...)); err != nil {
			return nil, err
		}
	}
	return o, nil
}

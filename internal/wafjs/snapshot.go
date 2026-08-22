package wafjs

import (
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/dop251/goja"
)

// RequestSnapshot is the curated, read-only view of one inbound request
// handed to the engine. It never carries *http.Request, directly or by
// reference. The snapshot ABI bead extends this type with the binary-safe
// body representation.
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

package wafjs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func hostWithJavascript(t *testing.T, js string) *Host {
	t.Helper()
	cfg := tempConfig(t, func(engine map[string]any) {
		engine["javascript"] = js
	}, nil)
	h := NewHost()
	if err := h.Build(context.Background(), cfg); err != nil {
		t.Fatalf("Host.Build() error = %v, want nil", err)
	}
	return h
}

func TestSnapshotRequestExposesWireBytesAsUint8Array(t *testing.T) {
	wire := []byte{0x00, 0xff, 0xfe, 'A', 0x80}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/upload?q=1", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}

	snap, err := SnapshotRequest(req, int64(len(wire)))
	if err != nil {
		t.Fatalf("SnapshotRequest(binary body) error = %v, want nil", err)
	}

	js := `(function () {
		globalThis.wafjsInspect = function (_tx, request) {
			if (!(request.body instanceof Uint8Array)) throw new Error("body is not Uint8Array");
			var want = [0, 255, 254, 65, 128];
			if (request.body.length !== want.length) throw new Error("body length changed");
			for (var i = 0; i < want.length; i++) {
				if (request.body[i] !== want[i]) throw new Error("body byte changed at " + i);
			}
			return {verdict:"allow",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:true,skip_reason:"",unsupported_features:[]};
		};
	})();`
	h := hostWithJavascript(t, js)
	_, err = h.Inspect(context.Background(), snap)
	if err != nil {
		t.Fatalf("Host.Inspect(binary snapshot) error = %v, want nil", err)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(restored body) error = %v, want nil", err)
	}
	if !bytes.Equal(restored, wire) {
		t.Errorf("SnapshotRequest(binary body) restored = %v, want %v", restored, wire)
	}
}

func TestSnapshotRequestWireByteFixtures(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty"},
		{name: "text", body: []byte("hello, world")},
		{name: "NUL bytes", body: []byte{'a', 0x00, 'b', 0x00}},
		{name: "invalid UTF-8", body: []byte{0xff, 0xfe, 0xc0, 0x80}},
		{name: "all byte classes", body: []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://example.test/fixtures", bytes.NewReader(tt.body))
			if err != nil {
				t.Fatalf("http.NewRequest(%q) error = %v, want nil", tt.name, err)
			}
			snap, err := SnapshotRequest(req, int64(len(tt.body)))
			if err != nil {
				t.Fatalf("SnapshotRequest(%q) error = %v, want nil", tt.name, err)
			}

			js := fmt.Sprintf(`(function () {
				globalThis.wafjsInspect = function (_tx, request) {
					var want = [%s];
					if (!(request.body instanceof Uint8Array)) throw new Error("body is not Uint8Array");
					if (request.body.length !== want.length) throw new Error("body length changed");
					for (var i = 0; i < want.length; i++) {
						if (request.body[i] !== want[i]) throw new Error("body byte changed at " + i);
					}
					return {verdict:"allow",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:true,skip_reason:"",unsupported_features:[]};
				};
			})();`, byteList(tt.body))
			h := hostWithJavascript(t, js)
			if _, err := h.Inspect(context.Background(), snap); err != nil {
				t.Errorf("Host.Inspect(%q) error = %v, want nil", tt.name, err)
			}
		})
	}
}

func TestSnapshotRequestCuratesFieldsAndIsolatesMutations(t *testing.T) {
	wire := []byte{0x00, 0xff, 'b', 'o', 'd', 'y'}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/a%2Fb?q=one&q=two", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v, want nil", err)
	}
	req.RequestURI = "/a%2Fb?q=one&q=two"
	req.Proto = "HTTP/2.0"
	req.Header["X-Test"] = []string{"one", "two"}
	req.AddCookie(&http.Cookie{Name: "session", Value: "original"})
	originalContentLength := req.ContentLength

	snap, err := SnapshotRequest(req, int64(len(wire)))
	if err != nil {
		t.Fatalf("SnapshotRequest(mutation fixture) error = %v, want nil", err)
	}

	js := `(function () {
		globalThis.wafjsInspect = function (_tx, request) {
			var wantKeys = ["body","body_truncated","cookies","headers","host","method","path","proto","query","request_uri","scheme"];
			var keys = Object.keys(request).sort();
			if (keys.join(",") !== wantKeys.join(",")) throw new Error("snapshot fields: " + keys.join(","));
			if (request.method !== "POST" || request.scheme !== "https" || request.host !== "example.test") throw new Error("metadata changed");
			if (request.request_uri !== "/a%2Fb?q=one&q=two" || request.path !== "/a/b" || request.proto !== "HTTP/2.0") throw new Error("request target changed");
			request.headers["X-Test"][0] = "mutated";
			request.headers["Injected"] = ["yes"];
			request.query.q[0] = "mutated";
			request.query.injected = ["yes"];
			request.cookies[0].name = "mutated";
			request.cookies[0].value = "mutated";
			request.cookies[1] = {name:"injected", value:"yes"};
			for (var i = 0; i < request.body.length; i++) request.body[i] = 0;
			return {verdict:"allow",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:true,skip_reason:"",unsupported_features:[]};
		};
	})();`
	if _, err := hostWithJavascript(t, js).Inspect(context.Background(), snap); err != nil {
		t.Fatalf("Host.Inspect(mutation fixture) error = %v, want nil", err)
	}

	if got := req.Header.Values("X-Test"); !equalStrings(got, []string{"one", "two"}) {
		t.Errorf("Host.Inspect() request headers = %v, want [one two]", got)
	}
	if got := req.Header.Get("Injected"); got != "" {
		t.Errorf("Host.Inspect() injected request header = %q, want empty", got)
	}
	if got := req.URL.Query()["q"]; !equalStrings(got, []string{"one", "two"}) {
		t.Errorf("Host.Inspect() request query = %v, want [one two]", got)
	}
	if got := req.URL.Query().Get("injected"); got != "" {
		t.Errorf("Host.Inspect() injected request query = %q, want empty", got)
	}
	cookies := req.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value != "original" {
		t.Errorf("Host.Inspect() request cookies = %v, want session=original", cookies)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(restored mutation body) error = %v, want nil", err)
	}
	if !bytes.Equal(restored, wire) {
		t.Errorf("Host.Inspect() restored body = %v, want %v", restored, wire)
	}
	if req.ContentLength != originalContentLength {
		t.Errorf("Host.Inspect() ContentLength = %d, want %d", req.ContentLength, originalContentLength)
	}
}

func TestSnapshotRequestRestoresBodyAtLimitBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		body          []byte
		limit         int64
		wantSnapshot  []byte
		wantTruncated bool
		wantRead      int
		wantClosedNow int
	}{
		{name: "under limit", body: []byte("abc"), limit: 5, wantSnapshot: []byte("abc"), wantRead: 3, wantClosedNow: 1},
		{name: "exact limit", body: []byte("abcde"), limit: 5, wantSnapshot: []byte("abcde"), wantRead: 5, wantClosedNow: 1},
		{name: "over limit", body: []byte("abcdefgh"), limit: 5, wantSnapshot: []byte("abcde"), wantTruncated: true, wantRead: 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &countingReadCloser{reader: &shortReader{data: tt.body, chunk: 2}}
			req := &http.Request{
				Method:        http.MethodPost,
				URL:           mustURL(t, "http://example.test/body"),
				Host:          "example.test",
				Proto:         "HTTP/1.1",
				Header:        make(http.Header),
				Body:          body,
				ContentLength: int64(len(tt.body)),
			}

			snap, err := SnapshotRequest(req, tt.limit)
			if err != nil {
				t.Fatalf("SnapshotRequest(%q) error = %v, want nil", tt.name, err)
			}
			if !bytes.Equal(snap.Body, tt.wantSnapshot) {
				t.Errorf("SnapshotRequest(%q).Body = %q, want %q", tt.name, snap.Body, tt.wantSnapshot)
			}
			if snap.BodyTruncated != tt.wantTruncated {
				t.Errorf("SnapshotRequest(%q).BodyTruncated = %t, want %t", tt.name, snap.BodyTruncated, tt.wantTruncated)
			}
			if body.bytesRead != tt.wantRead {
				t.Errorf("SnapshotRequest(%q) bytes read = %d, want %d", tt.name, body.bytesRead, tt.wantRead)
			}
			if body.closeCount != tt.wantClosedNow {
				t.Errorf("SnapshotRequest(%q) immediate closes = %d, want %d", tt.name, body.closeCount, tt.wantClosedNow)
			}
			if req.ContentLength != int64(len(tt.body)) {
				t.Errorf("SnapshotRequest(%q) ContentLength = %d, want %d", tt.name, req.ContentLength, len(tt.body))
			}

			restored, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("io.ReadAll(SnapshotRequest(%q).Body) error = %v, want nil", tt.name, err)
			}
			if !bytes.Equal(restored, tt.body) {
				t.Errorf("SnapshotRequest(%q) restored body = %q, want %q", tt.name, restored, tt.body)
			}
			if err := req.Body.Close(); err != nil {
				t.Errorf("SnapshotRequest(%q).Body.Close() error = %v, want nil", tt.name, err)
			}
			if err := req.Body.Close(); err != nil {
				t.Errorf("SnapshotRequest(%q).Body.Close() second error = %v, want nil", tt.name, err)
			}
			if body.closeCount != 1 {
				t.Errorf("SnapshotRequest(%q) original body closes = %d, want 1", tt.name, body.closeCount)
			}
		})
	}
}

func TestSnapshotRequestReadErrorReturnsTypedBodyFailure(t *testing.T) {
	wantErr := errors.New("fixture read failed")
	body := &countingReadCloser{reader: &errorReader{data: []byte("prefix"), err: wantErr}}
	req := &http.Request{
		Method:        http.MethodPost,
		URL:           mustURL(t, "http://example.test/error"),
		Host:          "example.test",
		Proto:         "HTTP/1.1",
		Header:        make(http.Header),
		Body:          body,
		ContentLength: 12,
	}

	_, err := SnapshotRequest(req, 64)
	if err == nil {
		t.Fatal("SnapshotRequest(read error) error = nil, want typed body failure")
	}
	var failure *Failure
	if !errors.As(err, &failure) {
		t.Fatalf("SnapshotRequest(read error) error type = %T, want *Failure", err)
	}
	if failure.Kind != FailureKindBody || failure.Reason != "read" {
		t.Errorf("SnapshotRequest(read error) failure = %s/%s, want body/read", failure.Kind, failure.Reason)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("SnapshotRequest(read error) errors.Is(%v) = false, want true", wantErr)
	}
	if req.ContentLength != 12 {
		t.Errorf("SnapshotRequest(read error) ContentLength = %d, want 12", req.ContentLength)
	}
	if body.closeCount != 0 {
		t.Errorf("SnapshotRequest(read error) immediate closes = %d, want 0", body.closeCount)
	}
	if err := req.Body.Close(); err != nil {
		t.Errorf("SnapshotRequest(read error).Body.Close() error = %v, want nil", err)
	}
	if err := req.Body.Close(); err != nil {
		t.Errorf("SnapshotRequest(read error).Body.Close() second error = %v, want nil", err)
	}
	if body.closeCount != 1 {
		t.Errorf("SnapshotRequest(read error) original body closes = %d, want 1", body.closeCount)
	}
}

type countingReadCloser struct {
	reader     io.Reader
	bytesRead  int
	closeCount int
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += n
	return n, err
}

func (r *countingReadCloser) Close() error {
	r.closeCount++
	return nil
}

type shortReader struct {
	data  []byte
	chunk int
}

func (r *shortReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(r.data), min(len(p), r.chunk))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func byteList(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join(parts, ",")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v, want nil", raw, err)
	}
	return u
}

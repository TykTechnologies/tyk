package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	oas "github.com/TykTechnologies/tyk/apidef/oas"
)

func newStripInboundMCPHeadersMW() *StripInboundMCPHeadersMiddleware {
	return &StripInboundMCPHeadersMiddleware{BaseMiddleware: &BaseMiddleware{}}
}

func TestStripInboundMCPHeaders_Name(t *testing.T) {
	mw := newStripInboundMCPHeadersMW()
	if got, want := mw.Name(), "StripInboundMCPHeaders"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestStripInboundMCPHeaders_EnabledForSpec(t *testing.T) {
	t.Run("nil spec returns false", func(t *testing.T) {
		mw := newStripInboundMCPHeadersMW()
		if mw.EnabledForSpec() {
			t.Fatalf("EnabledForSpec() = true, want false for nil Spec")
		}
	})

	t.Run("non-OAS spec returns false", func(t *testing.T) {
		mw := &StripInboundMCPHeadersMiddleware{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{IsOAS: false},
				},
			},
		}
		if mw.EnabledForSpec() {
			t.Fatalf("EnabledForSpec() = true, want false for non-OAS spec")
		}
	})

	t.Run("OAS without MCPProxy extension returns false", func(t *testing.T) {
		o := oas.OAS{}
		o.SetTykExtension(&oas.XTykAPIGateway{Server: oas.Server{}})
		mw := &StripInboundMCPHeadersMiddleware{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{IsOAS: true},
					OAS:           o,
				},
			},
		}
		if mw.EnabledForSpec() {
			t.Fatalf("EnabledForSpec() = true, want false when MCPProxy extension absent")
		}
	})

	t.Run("OAS with MCPProxy extension returns true", func(t *testing.T) {
		o := oas.OAS{}
		o.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				MCPProxy: &oas.MCPProxy{ProtocolVersion: "2025-06-18"},
			},
		})
		mw := &StripInboundMCPHeadersMiddleware{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{IsOAS: true},
					OAS:           o,
				},
			},
		}
		if !mw.EnabledForSpec() {
			t.Fatalf("EnabledForSpec() = false, want true when MCPProxy extension present")
		}
	})
}

func TestStripInboundMCPHeaders_StripsMCPHeadersAndPreservesOthers(t *testing.T) {
	mw := newStripInboundMCPHeadersMW()

	req, err := http.NewRequest("GET", "http://example.com/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Tyk-MCP-Context", `{"agent":"forged"}`)
	req.Header.Set("X-Tyk-MCP-Foo", "bar")
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Content-Type", "application/json")

	gotErr, code := mw.ProcessRequest(nil, req, nil)
	if gotErr != nil {
		t.Fatalf("ProcessRequest returned error: %v", gotErr)
	}
	if code != http.StatusOK {
		t.Fatalf("ProcessRequest code = %d, want %d", code, http.StatusOK)
	}

	if v := req.Header.Get("X-Tyk-MCP-Context"); v != "" {
		t.Errorf("X-Tyk-MCP-Context still present: %q", v)
	}
	if v := req.Header.Get("X-Tyk-MCP-Foo"); v != "" {
		t.Errorf("X-Tyk-MCP-Foo still present: %q", v)
	}
	if v := req.Header.Get("Authorization"); v != "Bearer x" {
		t.Errorf("Authorization = %q, want %q", v, "Bearer x")
	}
	if v := req.Header.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type = %q, want %q", v, "application/json")
	}

	// Belt and braces: scan all keys for any leftover MCP header.
	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-tyk-mcp-") {
			t.Errorf("found leftover MCP header after strip: %q", name)
		}
	}
}

func TestStripInboundMCPHeaders_MixedCaseRemoval(t *testing.T) {
	mw := newStripInboundMCPHeadersMW()

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Bypass http.Header canonicalisation by writing directly into the
	// underlying map, so we exercise the defensive lowercase comparison.
	req.Header["x-tyk-mcp-context"] = []string{"lower"}
	req.Header["X-TYK-MCP-Whatever"] = []string{"upper"}
	req.Header["X-Tyk-Mcp-Mixed"] = []string{"canonical"}
	req.Header.Set("Accept", "*/*")

	if gotErr, code := mw.ProcessRequest(nil, req, nil); gotErr != nil || code != http.StatusOK {
		t.Fatalf("ProcessRequest err=%v code=%d", gotErr, code)
	}

	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-tyk-mcp-") {
			t.Errorf("mixed-case header not removed: %q", name)
		}
	}
	if v := req.Header.Get("Accept"); v != "*/*" {
		t.Errorf("Accept = %q, want %q", v, "*/*")
	}
}

func TestStripInboundMCPHeaders_EmptyHeadersNoOp(t *testing.T) {
	mw := newStripInboundMCPHeadersMW()

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Force header map to empty (NewRequest may pre-populate).
	req.Header = http.Header{}

	gotErr, code := mw.ProcessRequest(nil, req, nil)
	if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}
	if code != http.StatusOK {
		t.Fatalf("code = %d, want %d", code, http.StatusOK)
	}
	if len(req.Header) != 0 {
		t.Fatalf("header set mutated unexpectedly: %v", req.Header)
	}
}

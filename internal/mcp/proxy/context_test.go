package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONRPCIDRoundTrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	// Absent before set.
	if _, ok := GetJSONRPCID(r); ok {
		t.Fatalf("expected no id before set")
	}

	// String id.
	r2 := SetJSONRPCID(r, "abc")
	got, ok := GetJSONRPCID(r2)
	if !ok || got != "abc" {
		t.Fatalf("string id round-trip: got=%v ok=%v", got, ok)
	}

	// Numeric id (json.Number-style float64 is the typical decoded form, but
	// we accept any so test with an int).
	r3 := SetJSONRPCID(r, 42)
	got, ok = GetJSONRPCID(r3)
	if !ok || got != 42 {
		t.Fatalf("int id round-trip: got=%v ok=%v", got, ok)
	}

	// Original request still has no id (immutability sanity-check).
	if _, ok := GetJSONRPCID(r); ok {
		t.Fatalf("original request mutated by SetJSONRPCID")
	}
}

func TestToolNameRoundTrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	if _, ok := GetToolName(r); ok {
		t.Fatalf("expected no tool name before set")
	}

	r2 := SetToolName(r, "hello-svc__get_hello")
	got, ok := GetToolName(r2)
	if !ok || got != "hello-svc__get_hello" {
		t.Fatalf("tool name round-trip: got=%q ok=%v", got, ok)
	}
}

func TestNilRequestSafe(t *testing.T) {
	// All accessors must tolerate a nil request without panicking.
	if r := SetJSONRPCID(nil, "x"); r != nil {
		t.Fatalf("SetJSONRPCID(nil) should return nil")
	}
	if r := SetToolName(nil, "x"); r != nil {
		t.Fatalf("SetToolName(nil) should return nil")
	}
	if v, ok := GetJSONRPCID(nil); ok || v != nil {
		t.Fatalf("GetJSONRPCID(nil) should return (nil,false)")
	}
	if v, ok := GetToolName(nil); ok || v != "" {
		t.Fatalf("GetToolName(nil) should return (\"\",false)")
	}
}

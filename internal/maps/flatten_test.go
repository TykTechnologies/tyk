package maps

import (
	"testing"
)

type flattenTestStruct struct {
	Name  string
	Count int
}

// Verifies: STK-REQ-022, SYS-REQ-110, SW-REQ-030
// STK-REQ-022:nominal:nominal
// STK-REQ-022:boundary:boundary
// SYS-REQ-110:nominal:nominal
// SYS-REQ-110:boundary:boundary
// SW-REQ-030:nominal:nominal
// SW-REQ-030:boundary:boundary
// MCDC SYS-REQ-110: maps_operation_requested=T, maps_operation_determined=T => TRUE
func TestFlatten(t *testing.T) {
	got, err := Flatten(map[string]interface{}{
		"bool_true":  true,
		"bool_false": false,
		"int":        7,
		"float":      1.25,
		"string":     "value",
		"nil":        nil,
		"nested": map[string]interface{}{
			"leaf": "ok",
		},
		"slice": []interface{}{"a", 2},
		"array": [2]string{"x", "y"},
		"struct": flattenTestStruct{
			Name:  "demo",
			Count: 3,
		},
	})
	if err != nil {
		t.Fatalf("Flatten returned error: %v", err)
	}

	want := FlatMap{
		"bool_true":    "true",
		"bool_false":   "false",
		"int":          "7",
		"float":        "1.250000",
		"string":       "value",
		"nil":          "",
		"nested.leaf":  "ok",
		"slice.0":      "a",
		"slice.1":      "2",
		"array.0":      "x",
		"array.1":      "y",
		"struct.Name":  "demo",
		"struct.Count": "3",
	}
	if len(got) != len(want) {
		t.Fatalf("Flatten returned %d entries, want %d: %#v", len(got), len(want), got)
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("Flatten[%q] = %q, want %q", key, got[key], wantValue)
		}
	}
}

// Verifies: STK-REQ-022, SYS-REQ-110, SW-REQ-030
// STK-REQ-022:malformed_input:negative
// SYS-REQ-110:malformed_input:negative
// SW-REQ-030:malformed_input:negative
func TestFlatten_UnsupportedValue(t *testing.T) {
	_, err := Flatten(map[string]interface{}{
		"unsupported": make(chan struct{}),
	})
	if err == nil {
		t.Fatal("Flatten did not return an error for unsupported value")
	}
}

// Verifies: STK-REQ-022, SYS-REQ-110, SW-REQ-030
// STK-REQ-022:malformed_input:negative
// SYS-REQ-110:malformed_input:negative
// SW-REQ-030:malformed_input:negative
func TestFlatten_NonStringMapKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Flatten did not panic for non-string map key")
		}
	}()

	_, _ = Flatten(map[string]interface{}{
		"invalid": map[int]string{1: "one"},
	})
}

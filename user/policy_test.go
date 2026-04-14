package user

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicy_PostExpiryAction_OmittedWhenUnset(t *testing.T) {
	p := Policy{ID: "p1", Name: "unset"}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if strings.Contains(string(b), "post_expiry_action") {
		t.Fatalf("expected post_expiry_action to be omitted when unset, got: %s", string(b))
	}
}

func TestPolicy_PostExpiryAction_IncludedWhenSet(t *testing.T) {
	p := Policy{ID: "p1", Name: "set", PostExpiryAction: PostExpiryActionRetain}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	raw, ok := decoded["post_expiry_action"]
	if !ok {
		t.Fatalf("expected post_expiry_action to be present when set, got: %s", string(b))
	}
	if string(raw) != `"retain"` {
		t.Fatalf("expected \"retain\", got %s", string(raw))
	}
}

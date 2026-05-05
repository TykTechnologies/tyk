package naming

import (
	"errors"
	"testing"
)

// TestSanitise covers the rules from RFC §9.2 sanitise_op: lowercase,
// replace disallowed characters with `_`, collapse `_+` to `_`, trim.
func TestSanitise(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain alnum", "getUserById", "getuserbyid"},
		{"already lower", "get_user", "get_user"},
		{"hyphen kept", "users-svc", "users-svc"},
		{"spaces become underscore", "Get User By Id", "get_user_by_id"},
		{"collapse runs", "a___b", "a_b"},
		{"trim leading trailing", "__abc__", "abc"},
		{"non-alnum replaced", "foo/bar.baz", "foo_bar_baz"},
		{"unicode replaced", "héllo", "h_llo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitise(tc.in)
			if got != tc.want {
				t.Fatalf("Sanitise(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEncodePath covers RFC §9.2 encode_path including templated
// segments and run-collapsing.
func TestEncodePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single static", "/hello", "hello"},
		{"static + var", "/users/{id}", "users_id"},
		{"plural static", "/users", "users"},
		{"v1 prefix", "/v1/users", "v1_users"},
		{"underscore-merging static", "/v1_users", "v1_users"},
		{"deep with var", "/a/b/{c}/d", "a_b_c_d"},
		{"no leading slash", "users/{id}", "users_id"},
		{"trailing slash", "/users/", "users"},
		{"symbols collapsed", "/foo--bar/{x}", "foo_bar_x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodePath(tc.in)
			if got != tc.want {
				t.Fatalf("EncodePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeriveOpName_RFCExamples is the verbatim §9.2 examples table.
func TestDeriveOpName_RFCExamples(t *testing.T) {
	type tc struct {
		method      string
		path        string
		operationID string
		slug        string
		wantOp      string
		wantTool    string
	}
	cases := []tc{
		{
			method: "GET", path: "/users/{id}", operationID: "getUserById",
			slug: "users-svc", wantOp: "getuserbyid", wantTool: "users-svc__getuserbyid",
		},
		{
			method: "GET", path: "/users/{id}", operationID: "",
			slug: "users-svc", wantOp: "get_users_id", wantTool: "users-svc__get_users_id",
		},
		{
			method: "POST", path: "/users", operationID: "",
			slug: "users-svc", wantOp: "post_users", wantTool: "users-svc__post_users",
		},
		{
			method: "GET", path: "/hello", operationID: "",
			slug: "hello-svc", wantOp: "get_hello", wantTool: "hello-svc__get_hello",
		},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path+"#"+c.operationID, func(t *testing.T) {
			used := map[string]struct{}{}
			gotOp, err := DeriveOpName(c.method, c.path, c.operationID, used)
			if err != nil {
				t.Fatalf("DeriveOpName: unexpected error: %v", err)
			}
			if gotOp != c.wantOp {
				t.Fatalf("op-name = %q, want %q", gotOp, c.wantOp)
			}
			gotTool := BuildToolName(c.slug, gotOp)
			if gotTool != c.wantTool {
				t.Fatalf("tool name = %q, want %q", gotTool, c.wantTool)
			}
		})
	}
}

// TestDeriveOpName_Collision exercises the §9.2 collision case:
// `GET /v1/users` and `GET /v1_users` both encode to `get_v1_users`.
func TestDeriveOpName_Collision(t *testing.T) {
	used := map[string]struct{}{}

	first, err := DeriveOpName("GET", "/v1/users", "", used)
	if err != nil {
		t.Fatalf("first DeriveOpName: unexpected error: %v", err)
	}
	if first != "get_v1_users" {
		t.Fatalf("first op-name = %q, want %q", first, "get_v1_users")
	}

	_, err = DeriveOpName("GET", "/v1_users", "", used)
	if err == nil {
		t.Fatalf("expected CollisionError, got nil")
	}

	var ce *CollisionError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CollisionError, got %T (%v)", err, err)
	}
	if ce.Candidate != "get_v1_users" {
		t.Fatalf("CollisionError.Candidate = %q, want %q", ce.Candidate, "get_v1_users")
	}
	if !errors.Is(err, ErrCollision) {
		t.Fatalf("errors.Is(err, ErrCollision) = false; want true")
	}

	// Make sure the failed insert did not pollute `used` beyond the first.
	if len(used) != 1 {
		t.Fatalf("used set size = %d, want 1", len(used))
	}
}

// TestDeriveOpName_OperationIDCollision verifies that explicit
// operationIds also collide when sanitised to the same candidate.
func TestDeriveOpName_OperationIDCollision(t *testing.T) {
	used := map[string]struct{}{}
	if _, err := DeriveOpName("GET", "/a", "getUserById", used); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := DeriveOpName("GET", "/b", "GetUserById", used)
	if !errors.Is(err, ErrCollision) {
		t.Fatalf("expected ErrCollision, got %v", err)
	}
}

// TestBuildToolName_RoundTrip verifies the `__` separator round-trip:
// BuildToolName("a_b", "c_d") -> "a_b__c_d", and SplitToolName recovers
// the inputs from a single split on the first `__`.
func TestBuildToolName_RoundTrip(t *testing.T) {
	got := BuildToolName("a_b", "c_d")
	want := "a_b__c_d"
	if got != want {
		t.Fatalf("BuildToolName = %q, want %q", got, want)
	}

	slug, op, ok := SplitToolName(got)
	if !ok {
		t.Fatalf("SplitToolName(%q) ok=false", got)
	}
	if slug != "a_b" || op != "c_d" {
		t.Fatalf("SplitToolName = (%q, %q), want (%q, %q)", slug, op, "a_b", "c_d")
	}
}

// TestBuildToolName_UnderscoreCollapse documents that runs of `_` inside
// either token are collapsed by Sanitise, so the literal `__` only ever
// appears as the separator. This is what makes the single-split
// round-trip lossless even when raw inputs contain consecutive `_`.
func TestBuildToolName_UnderscoreCollapse(t *testing.T) {
	got := BuildToolName("a__b", "c___d")
	want := "a_b__c_d"
	if got != want {
		t.Fatalf("BuildToolName = %q, want %q", got, want)
	}
	slug, op, ok := SplitToolName(got)
	if !ok || slug != "a_b" || op != "c_d" {
		t.Fatalf("split = (%q, %q, %v), want (a_b, c_d, true)", slug, op, ok)
	}
}

// TestSplitToolName_NoSeparator returns ok=false when the separator is
// absent.
func TestSplitToolName_NoSeparator(t *testing.T) {
	if _, _, ok := SplitToolName("no-separator-here"); ok {
		t.Fatalf("expected ok=false for input without %q", Separator)
	}
}

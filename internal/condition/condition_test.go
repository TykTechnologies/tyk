package condition

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompile_EmptyString(t *testing.T) {
	fn, err := Compile("")
	require.NoError(t, err)
	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
}

func TestCompile_Whitespace(t *testing.T) {
	fn, err := Compile("   ")
	require.NoError(t, err)
	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
}

func TestCompile_InvalidSyntax(t *testing.T) {
	_, err := Compile("request.method ==")
	assert.Error(t, err)
}

func TestCompile_UnknownNamespace(t *testing.T) {
	_, err := Compile(`unknown.field == "val"`)
	assert.Error(t, err)
}

func TestCompile_BadRegex(t *testing.T) {
	_, err := Compile(`request.path matches "[invalid"`)
	assert.Error(t, err)
}

func TestEval_RequestMethod(t *testing.T) {
	fn, err := Compile(`request.method == "GET"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
	assert.False(t, fn(httptest.NewRequest("POST", "/", nil), nil))
}

func TestEval_RequestPath(t *testing.T) {
	fn, err := Compile(`request.path == "/api/v1"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/api/v1", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/api/v2", nil), nil))
}

func TestEval_RequestHeaders(t *testing.T) {
	fn, err := Compile(`request.headers["X-Test"] == "hello"`)
	require.NoError(t, err)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", "hello")
	assert.True(t, fn(r, nil))

	r2 := httptest.NewRequest("GET", "/", nil)
	assert.False(t, fn(r2, nil))
}

func TestEval_RequestParams(t *testing.T) {
	fn, err := Compile(`request.params["key"] == "val"`)
	require.NoError(t, err)

	r := httptest.NewRequest("GET", "/?key=val", nil)
	assert.True(t, fn(r, nil))

	r2 := httptest.NewRequest("GET", "/?key=other", nil)
	assert.False(t, fn(r2, nil))
}

type testContextKey struct{}

func TestEval_ContextData(t *testing.T) {
	oldKey := ContextDataKey
	ContextDataKey = testContextKey{}
	defer func() { ContextDataKey = oldKey }()

	fn, err := Compile(`context["tenant"] == "acme"`)
	require.NoError(t, err)

	r := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(r.Context(), testContextKey{}, map[string]interface{}{
		"tenant": "acme",
	})
	r = r.WithContext(ctx)
	assert.True(t, fn(r, nil))

	r2 := httptest.NewRequest("GET", "/", nil)
	assert.False(t, fn(r2, nil))
}

func TestEval_SessionMetadata(t *testing.T) {
	fn, err := Compile(`session.metadata["tier"] == "premium"`)
	require.NoError(t, err)

	meta := map[string]interface{}{
		"tier": "premium",
	}
	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), meta))
	assert.False(t, fn(httptest.NewRequest("GET", "/", nil), nil))
}

func TestEval_NotEqual(t *testing.T) {
	fn, err := Compile(`request.method != "GET"`)
	require.NoError(t, err)

	assert.False(t, fn(httptest.NewRequest("GET", "/", nil), nil))
	assert.True(t, fn(httptest.NewRequest("POST", "/", nil), nil))
}

func TestEval_Contains(t *testing.T) {
	fn, err := Compile(`request.path contains "/api"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/api/v1", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/health", nil), nil))
}

func TestEval_Matches(t *testing.T) {
	fn, err := Compile(`request.path matches "^/api/v[0-9]+"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/api/v1", nil), nil))
	assert.True(t, fn(httptest.NewRequest("GET", "/api/v23/foo", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/health", nil), nil))
}

func TestEval_And(t *testing.T) {
	fn, err := Compile(`request.method == "POST" && request.path == "/api"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("POST", "/api", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/api", nil), nil))
	assert.False(t, fn(httptest.NewRequest("POST", "/other", nil), nil))
}

func TestEval_Or(t *testing.T) {
	fn, err := Compile(`request.method == "GET" || request.method == "HEAD"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
	assert.True(t, fn(httptest.NewRequest("HEAD", "/", nil), nil))
	assert.False(t, fn(httptest.NewRequest("POST", "/", nil), nil))
}

func TestEval_Not(t *testing.T) {
	fn, err := Compile(`!(request.method == "GET")`)
	require.NoError(t, err)

	assert.False(t, fn(httptest.NewRequest("GET", "/", nil), nil))
	assert.True(t, fn(httptest.NewRequest("POST", "/", nil), nil))
}

func TestEval_Parentheses(t *testing.T) {
	fn, err := Compile(`(request.method == "GET" || request.method == "HEAD") && request.path == "/api"`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("GET", "/api", nil), nil))
	assert.True(t, fn(httptest.NewRequest("HEAD", "/api", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/other", nil), nil))
	assert.False(t, fn(httptest.NewRequest("POST", "/api", nil), nil))
}

func TestEval_Nested(t *testing.T) {
	fn, err := Compile(`!(request.method == "GET" && request.path contains "/admin")`)
	require.NoError(t, err)

	assert.True(t, fn(httptest.NewRequest("POST", "/admin", nil), nil))
	assert.True(t, fn(httptest.NewRequest("GET", "/api", nil), nil))
	assert.False(t, fn(httptest.NewRequest("GET", "/admin/users", nil), nil))
}

func TestEval_MissingHeader(t *testing.T) {
	fn, err := Compile(`request.headers["Missing"] == ""`)
	require.NoError(t, err)
	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
}

func TestEval_NilSession(t *testing.T) {
	fn, err := Compile(`session.metadata["key"] == ""`)
	require.NoError(t, err)
	assert.True(t, fn(httptest.NewRequest("GET", "/", nil), nil))
}

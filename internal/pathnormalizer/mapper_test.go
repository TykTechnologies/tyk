package pathnormalizer

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// patternOf returns the schema pattern of the named path parameter of entry.
func patternOf(t *testing.T, entry Entry, name string) string {
	t.Helper()

	for _, ref := range entry.pathParameters() {
		require.NotNil(t, ref.Value)

		if ref.Value.Name != name {
			continue
		}

		require.NotNil(t, ref.Value.Schema)
		require.NotNil(t, ref.Value.Schema.Value)

		return ref.Value.Schema.Value.Pattern
	}

	t.Fatalf("path parameter %q not found on %s", name, entry.Normalized)
	return ""
}

// TestMapper_FindOrCreate_regexCollision covers endpoints that sit at the same
// position in the URL and are told apart only by their regex. Each one has to
// keep its own placeholder and its own pattern, while endpoints that differ only
// by HTTP method keep sharing a single normalized path.
func TestMapper_FindOrCreate_regexCollision(t *testing.T) {
	mapper, err := NewMapper(openapi3.NewPaths())
	require.NoError(t, err)

	numeric, err := mapper.FindOrCreate("/user/[0-9]+", "GET")
	require.NoError(t, err)

	alpha, err := mapper.FindOrCreate("/user/[a-zA-Z]+", "GET")
	require.NoError(t, err)

	assert.Equal(t, "/user/{customRegex1}", numeric.Normalized)
	assert.Equal(t, "/user/{customRegex2}", alpha.Normalized)
	assert.NotEqual(t, numeric.Normalized, alpha.Normalized,
		"endpoints differing only by regex must not collapse onto one path")

	assert.Equal(t, "[0-9]+", patternOf(t, numeric, "customRegex1"))
	assert.Equal(t, "[a-zA-Z]+", patternOf(t, alpha, "customRegex2"))

	assert.Equal(t, "user/[0-9]+GET", numeric.OperationID)
	assert.Equal(t, "user/[a-zA-Z]+GET", alpha.OperationID)
}

// TestMapper_FindOrCreate_sharedAcrossMethods pins that normalization is
// memoised per path rather than per endpoint, so a second HTTP method on the
// same path does not mint a fresh placeholder name.
func TestMapper_FindOrCreate_sharedAcrossMethods(t *testing.T) {
	mapper, err := NewMapper(openapi3.NewPaths())
	require.NoError(t, err)

	get, err := mapper.FindOrCreate("/user/[0-9]+", "GET")
	require.NoError(t, err)

	post, err := mapper.FindOrCreate("/user/[0-9]+", "POST")
	require.NoError(t, err)

	assert.Equal(t, get.Normalized, post.Normalized)
	assert.Equal(t, "/user/{customRegex1}", post.Normalized)
	assert.Equal(t, "[0-9]+", patternOf(t, post, "customRegex1"))

	// The operation ID still distinguishes the two endpoints.
	assert.Equal(t, "user/[0-9]+GET", get.OperationID)
	assert.Equal(t, "user/[0-9]+POST", post.OperationID)
}

// TestMapper_FindOrCreate_multipleRegexPerPath covers a single path carrying
// more than one regex segment: the placeholders are numbered left to right and
// each keeps its own pattern.
func TestMapper_FindOrCreate_multipleRegexPerPath(t *testing.T) {
	mapper, err := NewMapper(openapi3.NewPaths())
	require.NoError(t, err)

	entry, err := mapper.FindOrCreate("/user/[a-zA-Z]+/account/[0-9]+", "GET")
	require.NoError(t, err)

	assert.Equal(t, "/user/{customRegex1}/account/{customRegex2}", entry.Normalized)
	assert.Equal(t, "[a-zA-Z]+", patternOf(t, entry, "customRegex1"))
	assert.Equal(t, "[0-9]+", patternOf(t, entry, "customRegex2"))
}

// TestMapper_FindOrCreate_plainPath pins that a path without regex is left alone.
func TestMapper_FindOrCreate_plainPath(t *testing.T) {
	mapper, err := NewMapper(openapi3.NewPaths())
	require.NoError(t, err)

	entry, err := mapper.FindOrCreate("/plain/path", "GET")
	require.NoError(t, err)

	assert.Equal(t, "/plain/path", entry.Normalized)
	assert.Empty(t, entry.pathParameters())
}

// seededPaths builds a document that already carries one normalized regex path,
// as happens whenever a classic API is filled onto an existing OAS document.
func seededPaths(schema *openapi3.Schema) *openapi3.Paths {
	paths := openapi3.NewPaths()

	item := &openapi3.PathItem{}
	item.SetOperation("GET", &openapi3.Operation{OperationID: "user/[0-9]+GET"})
	item.Parameters = openapi3.Parameters{{Value: &openapi3.Parameter{
		Name:     "customRegex1",
		In:       "path",
		Required: true,
		Schema:   &openapi3.SchemaRef{Value: schema},
	}}}
	paths.Set("/user/{customRegex1}", item)

	return paths
}

// TestMapper_FindOrCreate_seededDocument covers filling onto a document that
// already uses customRegex1: the next anonymous placeholder has to step over it
// rather than collide with it.
func TestMapper_FindOrCreate_seededDocument(t *testing.T) {
	mapper, err := NewMapper(seededPaths(openapi3.NewStringSchema().WithPattern("[0-9]+")))
	require.NoError(t, err)

	entry, err := mapper.FindOrCreate("/user/[a-zA-Z]+", "GET")
	require.NoError(t, err)

	assert.Equal(t, "/user/{customRegex2}", entry.Normalized)
	assert.Equal(t, "[a-zA-Z]+", patternOf(t, entry, "customRegex2"))

	// The path already in the document is reachable under its own name.
	existing, err := mapper.FindOrCreate("/user/{customRegex1}", "GET")
	require.NoError(t, err)
	assert.Equal(t, "/user/{customRegex1}", existing.Normalized)
}

// TestMapper_untypedParameterSchema covers a path parameter whose schema omits
// "type". That is valid OAS, and it must not fault the mapper.
func TestMapper_untypedParameterSchema(t *testing.T) {
	mapper, err := NewMapper(seededPaths(&openapi3.Schema{Pattern: "[0-9]+"}))
	require.NoError(t, err)

	entry, err := mapper.FindOrCreate("/user/[a-zA-Z]+", "GET")
	require.NoError(t, err)
	assert.Equal(t, "/user/{customRegex2}", entry.Normalized)
}

// TestMapper_FindOrCreate_refill covers filling a Classic API onto an OAS
// document that an earlier fill of that same API produced. The dashboard does
// this on every API save, so it has to land on the existing path rather than
// mint a second one or fail as a collision.
func TestMapper_FindOrCreate_refill(t *testing.T) {
	first, err := NewMapper(openapi3.NewPaths())
	require.NoError(t, err)

	created, err := first.FindOrCreate("/user/[0-9]+", "GET")
	require.NoError(t, err)
	require.Equal(t, "/user/{customRegex1}", created.Normalized)

	// Rebuild the document the way a fill would leave it, then fill again.
	doc := openapi3.NewPaths()
	item := &openapi3.PathItem{}
	item.SetOperation("GET", &openapi3.Operation{OperationID: created.OperationID})
	item.Parameters = openapi3.Parameters{}
	created.ExtendPathParameters(&item.Parameters)
	doc.Set(created.Normalized, item)

	second, err := NewMapper(doc)
	require.NoError(t, err)

	again, err := second.FindOrCreate("/user/[0-9]+", "GET")
	require.NoError(t, err, "re-filling an API onto its own output must not collide")
	assert.Equal(t, created.Normalized, again.Normalized)
	assert.Equal(t, "[0-9]+", patternOf(t, again, "customRegex1"))

	// A genuinely new endpoint still gets a name of its own.
	other, err := second.FindOrCreate("/user/[a-zA-Z]+", "GET")
	require.NoError(t, err)
	assert.Equal(t, "/user/{customRegex2}", other.Normalized)
}

package oas

import (
	"net/http"
	"sort"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// classicWithWhiteList builds the smallest Classic definition that carries the
// given endpoints through a conversion.
func classicWithWhiteList(endpoints ...apidef.EndPointMeta) apidef.APIDefinition {
	var api apidef.APIDefinition

	api.VersionData.Versions = map[string]apidef.VersionInfo{
		Main: {ExtendedPaths: apidef.ExtendedPathsSet{WhiteList: endpoints}},
	}

	return api
}

// pathKeysOf lists the path keys of a document, sorted, for stable assertions.
func pathKeysOf(paths *openapi3.Paths) []string {
	keys := make([]string, 0, paths.Len())
	for key := range paths.Map() {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// patternsOf maps each path parameter to the regex on its schema.
func patternsOf(params openapi3.Parameters) map[string]string {
	out := make(map[string]string, len(params))

	for _, ref := range params {
		if ref == nil || ref.Value == nil || ref.Value.In != openapi3.ParameterInPath {
			continue
		}

		var pattern string
		if ref.Value.Schema != nil && ref.Value.Schema.Value != nil {
			pattern = ref.Value.Schema.Value.Pattern
		}

		out[ref.Value.Name] = pattern
	}

	return out
}

// TestOAS_Fill_legacyConversionUnchanged guards the frozen contract. Fill is the
// ordinary cycle, run on every load and save of an OAS API, and customers route
// on the behaviour it produces. It must keep converting exactly as it always
// has, including the parts that look like defects:
//
//   - two endpoints differing only by their regex still collapse onto one path,
//     the second overwriting the first;
//   - a mux parameter is left unconstrained, and one carrying its own regex
//     loses it.
//
// Migration is where those are fixed. If this test starts failing, the two
// conversions have been merged back together and customers' routing has moved
// under them.
func TestOAS_Fill_legacyConversionUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("overlapping regexes still collapse", func(t *testing.T) {
		t.Parallel()

		var s OAS
		s.Fill(classicWithWhiteList(
			apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodGet},
			apidef.EndPointMeta{Path: "/user/[a-zA-Z]+", Method: http.MethodGet},
		))

		assert.Equal(t, []string{"/user/{customRegex1}"}, pathKeysOf(s.Paths))

		pathItem := s.Paths.Value("/user/{customRegex1}")
		require.NotNil(t, pathItem)
		assert.Equal(t, map[string]string{"customRegex1": "[0-9]+"}, patternsOf(pathItem.Parameters))
	})

	t.Run("mux parameters keep losing their pattern", func(t *testing.T) {
		t.Parallel()

		var s OAS
		s.Fill(classicWithWhiteList(
			apidef.EndPointMeta{Path: "/user/{id}", Method: http.MethodGet},
			apidef.EndPointMeta{Path: "/acc/{accId:[0-9]+}", Method: http.MethodGet},
		))

		plain := s.Paths.Value("/user/{id}")
		require.NotNil(t, plain)
		assert.Equal(t, map[string]string{"id": ""}, patternsOf(plain.Parameters))

		withRegex := s.Paths.Value("/acc/{accId}")
		require.NotNil(t, withRegex)
		assert.Equal(t, map[string]string{"accId": ""}, patternsOf(withRegex.Parameters))
	})
}

// TestOAS_fillForMigration_overlappingRegexEndpoints is the case TT-18228
// describes: two Classic endpoints at the same position in the URL, told apart
// only by their regex. Migration has to keep both, each under a path key of its
// own and holding its own pattern.
func TestOAS_fillForMigration_overlappingRegexEndpoints(t *testing.T) {
	t.Parallel()

	var s OAS
	require.NoError(t, s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodGet},
		apidef.EndPointMeta{Path: "/user/[a-zA-Z]+", Method: http.MethodGet},
	)))

	assert.Equal(t, []string{"/user/{customRegex1}", "/user/{customRegex2}"}, pathKeysOf(s.Paths))

	numeric := s.Paths.Value("/user/{customRegex1}")
	require.NotNil(t, numeric)
	assert.Equal(t, map[string]string{"customRegex1": "[0-9]+"}, patternsOf(numeric.Parameters))

	alpha := s.Paths.Value("/user/{customRegex2}")
	require.NotNil(t, alpha)
	assert.Equal(t, map[string]string{"customRegex2": "[a-zA-Z]+"}, patternsOf(alpha.Parameters))

	require.NotNil(t, numeric.Get)
	require.NotNil(t, alpha.Get)
	assert.Equal(t, "user/[0-9]+GET", numeric.Get.OperationID)
	assert.Equal(t, "user/[a-zA-Z]+GET", alpha.Get.OperationID)
}

// TestOAS_fillForMigration_sameRegexAcrossMethods pins that endpoints differing
// only by method keep sharing one path item.
func TestOAS_fillForMigration_sameRegexAcrossMethods(t *testing.T) {
	t.Parallel()

	var s OAS
	require.NoError(t, s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodGet},
		apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodPost},
	)))

	assert.Equal(t, []string{"/user/{customRegex1}"}, pathKeysOf(s.Paths))

	pathItem := s.Paths.Value("/user/{customRegex1}")
	require.NotNil(t, pathItem)
	require.NotNil(t, pathItem.Get)
	require.NotNil(t, pathItem.Post)

	assert.Len(t, pathItem.Parameters, 1, "one parameter, not one per method")
	assert.Equal(t, map[string]string{"customRegex1": "[0-9]+"}, patternsOf(pathItem.Parameters))
}

// TestOAS_fillForMigration_multipleRegexInOnePath covers several regex segments
// in one path: numbered left to right, each keeping its own pattern.
func TestOAS_fillForMigration_multipleRegexInOnePath(t *testing.T) {
	t.Parallel()

	var s OAS
	require.NoError(t, s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/[a-zA-Z]+/account/[0-9]+", Method: http.MethodGet},
	)))

	assert.Equal(t, []string{"/user/{customRegex1}/account/{customRegex2}"}, pathKeysOf(s.Paths))

	pathItem := s.Paths.Value("/user/{customRegex1}/account/{customRegex2}")
	require.NotNil(t, pathItem)
	assert.Equal(t, map[string]string{
		"customRegex1": "[a-zA-Z]+",
		"customRegex2": "[0-9]+",
	}, patternsOf(pathItem.Parameters))
}

// TestOAS_fillForMigration_isStable covers migrating onto the document an
// earlier migration produced: it must land on the paths already there.
func TestOAS_fillForMigration_isStable(t *testing.T) {
	t.Parallel()

	classic := classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodGet},
		apidef.EndPointMeta{Path: "/user/[a-zA-Z]+", Method: http.MethodGet},
	)

	var s OAS
	require.NoError(t, s.fillForMigration(classic))

	before := pathKeysOf(s.Paths)

	require.NoError(t, s.fillForMigration(classic))

	assert.Equal(t, before, pathKeysOf(s.Paths), "a second migration must not add paths")

	for _, key := range before {
		pathItem := s.Paths.Value(key)
		require.NotNil(t, pathItem)
		assert.Lenf(t, pathItem.Parameters, 1, "path %s gained duplicate parameters", key)
	}
}

// TestOAS_fillForMigration_reportsWhatItCannotConvert covers an endpoint whose
// path the parser rejects. Not every Classic API can be migrated, and the user
// asking for the migration is the one who needs to hear about it, so the failure
// is reported rather than logged and stepped over.
func TestOAS_fillForMigration_reportsWhatItCannotConvert(t *testing.T) {
	t.Parallel()

	var s OAS
	err := s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/{", Method: http.MethodGet},
		apidef.EndPointMeta{Path: "/team/{", Method: http.MethodPost},
	))

	require.Error(t, err)

	// Every failing endpoint is named, not just the first one, so one attempt
	// tells the user everything that stands in the way.
	assert.Contains(t, err.Error(), "GET /user/{")
	assert.Contains(t, err.Error(), "POST /team/{")
}

// TestOAS_fillForMigration_skipsWhatItCannotConvert pins that an endpoint the
// mapper cannot place is left out of the document altogether, while the rest of
// the API still converts.
//
// Carrying on with the empty operation ID it returns was worse than losing the
// endpoint: every failing endpoint keyed its middleware under "" in the Tyk
// extension and merged into a single operation there, and the helpers that look
// the operation back up afterwards dereferenced a nil path item.
func TestOAS_fillForMigration_skipsWhatItCannotConvert(t *testing.T) {
	t.Parallel()

	var s OAS
	err := s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/{", Method: http.MethodGet},
		apidef.EndPointMeta{Path: "/ok/[0-9]+", Method: http.MethodGet},
	))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /user/{")

	// The endpoints that could be converted still are.
	assert.Equal(t, []string{"/ok/{customRegex1}"}, pathKeysOf(s.Paths))

	middleware := s.GetTykExtension().Middleware
	require.NotNil(t, middleware)
	assert.NotContains(t, middleware.Operations, "",
		"a skipped endpoint must not key middleware under an empty operation ID")
	assert.Contains(t, middleware.Operations, "ok/[0-9]+GET")
}

// TestOAS_fillForMigration_reportsUnreadableDocument covers a document that
// already holds a path the parser rejects: the migration says so instead of
// silently converting onto an unseeded mapper.
func TestOAS_fillForMigration_reportsUnreadableDocument(t *testing.T) {
	t.Parallel()

	var s OAS
	s.Paths = openapi3.NewPaths()
	s.Paths.Set("/user/{", &openapi3.PathItem{Get: &openapi3.Operation{}})

	err := s.fillForMigration(classicWithWhiteList(
		apidef.EndPointMeta{Path: "/user/[0-9]+", Method: http.MethodGet},
	))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read the existing paths")
}

// TestOAS_usesGeneratedPlaceholders pins what marks a document as one migration
// produced, since that is what decides which conversion the ordinary fill cycle
// uses.
func TestOAS_usesGeneratedPlaceholders(t *testing.T) {
	t.Parallel()

	docWith := func(name, pattern string) *OAS {
		schema := openapi3.NewStringSchema()
		if pattern != "" {
			schema = schema.WithPattern(pattern)
		}

		item := &openapi3.PathItem{}
		item.SetOperation(http.MethodGet, &openapi3.Operation{})
		item.Parameters = openapi3.Parameters{{Value: &openapi3.Parameter{
			Name: name, In: openapi3.ParameterInPath, Required: true,
			Schema: &openapi3.SchemaRef{Value: schema},
		}}}

		s := &OAS{}
		s.Paths = openapi3.NewPaths()
		s.Paths.Set("/users/{"+name+"}", item)

		return s
	}

	assert.True(t, docWith("customRegex1", "[a-z]+").usesGeneratedPlaceholders())
	assert.False(t, docWith("customRegex1", "").usesGeneratedPlaceholders(),
		"a placeholder carrying no regex is not migration output")
	assert.False(t, docWith("userId", "[a-z]+").usesGeneratedPlaceholders(),
		"a parameter the user named is not migration output")
	assert.False(t, (&OAS{}).usesGeneratedPlaceholders(), "an empty document has no paths")
}

// TestOAS_Fill_keepsMiddlewareOnItsOwnEndpoint covers the state the dashboard
// stores while staging a migration: the migrated OAS next to a Classic
// definition that still holds the original regex paths. Filling that with the
// legacy conversion resolved both Classic paths to {customRegex1}, so the
// second endpoint wrote its mock response body onto the first one's operation.
func TestOAS_Fill_keepsMiddlewareOnItsOwnEndpoint(t *testing.T) {
	t.Parallel()

	var classic apidef.APIDefinition
	classic.VersionData.Versions = map[string]apidef.VersionInfo{
		Main: {ExtendedPaths: apidef.ExtendedPathsSet{
			WhiteList: []apidef.EndPointMeta{
				{Path: "/users/[a-z]+", Method: http.MethodGet},
				{Path: "/users/[0-9]+", Method: http.MethodGet},
			},
			MockResponse: []apidef.MockResponseMeta{
				{Path: "/users/[a-z]+", Method: http.MethodGet, Code: 200, Body: `{"by_name":true}`},
				{Path: "/users/[0-9]+", Method: http.MethodGet, Code: 200, Body: `{"by_number":true}`},
			},
		}},
	}

	var s OAS
	require.NoError(t, s.fillForMigration(classic))
	require.Equal(t, []string{"/users/{customRegex1}", "/users/{customRegex2}"}, pathKeysOf(s.Paths))

	// The save the dashboard performs next, over the Classic side migration left.
	s.Fill(classic)

	operations := s.GetTykExtension().Middleware.Operations
	require.Contains(t, operations, "users/[a-z]+GET")
	require.Contains(t, operations, "users/[0-9]+GET")
	require.NotNil(t, operations["users/[a-z]+GET"].MockResponse)
	require.NotNil(t, operations["users/[0-9]+GET"].MockResponse)

	assert.Equal(t, `{"by_name":true}`, operations["users/[a-z]+GET"].MockResponse.Body)
	assert.Equal(t, `{"by_number":true}`, operations["users/[0-9]+GET"].MockResponse.Body)
}

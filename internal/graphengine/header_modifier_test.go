package graphengine

// The upstream header modifier of both graphql-go-tools versions. It is the one place where
// a dynamic header value gets resolved, and it has to happen there rather than on the way to
// the wire: the library applies the modifier before it computes the key that decides whether
// two callers share an upstream subscription connection. See connectionKey in the v1
// subscription client and UniqueRequestID in the v2 resolver.
//
// The two modifiers are the same function twice over, so the cases run against either.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headerModifierConstructor builds the modifier under test.
type headerModifierConstructor func(outreq *http.Request, additionalHeaders http.Header, variableReplacer TykVariableReplacer) func(http.Header)

func TestGraphqlGoToolsV1_HeaderModifier(t *testing.T) {
	runHeaderModifierCases(t, func(outreq *http.Request, additionalHeaders http.Header, variableReplacer TykVariableReplacer) func(http.Header) {
		return graphqlGoToolsV1{}.headerModifier(outreq, additionalHeaders, variableReplacer)
	})
}

func TestGraphqlGoToolsV2_HeaderModifier(t *testing.T) {
	runHeaderModifierCases(t, func(outreq *http.Request, additionalHeaders http.Header, variableReplacer TykVariableReplacer) func(http.Header) {
		return graphqlGoToolsV2{}.headerModifier(outreq, additionalHeaders, variableReplacer)
	})
}

// newHeaderModifierRequest builds a caller request that carries caller in X-Caller, which is
// what testHeaderVariableReplacer resolves $tyk_context.caller from.
func newHeaderModifierRequest(caller string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://gateway.example/graphql", nil)
	request.Header.Set("X-Caller", caller)
	return request
}

// testHeaderVariableReplacer stands in for Gateway.ReplaceTykVariables. It resolves against
// the request it is handed, so a value that leaks in from another caller is visible.
func testHeaderVariableReplacer(request *http.Request, value string, _ bool) string {
	return strings.ReplaceAll(value, "$tyk_context.caller", request.Header.Get("X-Caller"))
}

func runHeaderModifierCases(t *testing.T, newModifier headerModifierConstructor) {
	t.Helper()

	t.Run("resolves the variable in every value of a multi value header", func(t *testing.T) {
		header := http.Header{
			"X-Api-Key": {"$tyk_context.caller", "prefix-$tyk_context.caller"},
		}
		additional := http.Header{"X-Static": {"one", "two"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, testHeaderVariableReplacer)(header)

		assert.Equal(t, []string{"caller-a", "prefix-caller-a"}, header.Values("X-Api-Key"))
		assert.Equal(t, []string{"one", "two"}, header.Values("X-Static"))
	})

	t.Run("resolves an additional header too", func(t *testing.T) {
		// The dynamic UDG global header, which is how an API definition asks for the
		// caller's credential to be forwarded upstream.
		header := http.Header{}
		additional := http.Header{"X-Upstream-Authorization": {"Bearer $tyk_context.caller"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, testHeaderVariableReplacer)(header)

		assert.Equal(t, []string{"Bearer caller-a"}, header.Values("X-Upstream-Authorization"))
	})

	t.Run("an existing header value wins over an additional header", func(t *testing.T) {
		header := http.Header{"X-Api-Key": {"from-the-data-source"}}
		additional := http.Header{"X-Api-Key": {"from-tyk"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, testHeaderVariableReplacer)(header)

		assert.Equal(t, []string{"from-the-data-source"}, header.Values("X-Api-Key"))
	})

	t.Run("a multi value additional header is copied whole", func(t *testing.T) {
		// Not reachable from an API definition, where both the UDG global headers and the
		// data source headers are single valued, but the connection key of a subscription
		// is built from every value, so dropping one would silently merge two callers.
		header := http.Header{}
		additional := http.Header{"X-Api-Key": {"first", "second", "third"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, testHeaderVariableReplacer)(header)

		assert.Equal(t, []string{"first", "second", "third"}, header.Values("X-Api-Key"))
	})

	t.Run("a nil replacer merges the additional headers and resolves nothing", func(t *testing.T) {
		header := http.Header{"X-Api-Key": {"$tyk_context.caller"}}
		additional := http.Header{"X-Static": {"one"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, nil)(header)

		assert.Equal(t, []string{"$tyk_context.caller"}, header.Values("X-Api-Key"))
		assert.Equal(t, []string{"one"}, header.Values("X-Static"))
	})

	t.Run("a non canonical additional header key lands under the canonical one", func(t *testing.T) {
		// The modifier assigns into the map to keep multiple values, and a map write does
		// no canonicalisation, so it has to do it itself. Otherwise the key it writes is
		// one that Get, Values and the upstream request cannot read back.
		header := http.Header{}
		additional := http.Header{"x-api-key": {"from-tyk"}}

		newModifier(newHeaderModifierRequest("caller-a"), additional, testHeaderVariableReplacer)(header)

		assert.Equal(t, []string{"from-tyk"}, header.Values("X-Api-Key"))
		assert.NotContains(t, header, "x-api-key")
	})

	t.Run("resolves against the request of this caller", func(t *testing.T) {
		request := newHeaderModifierRequest("caller-a")
		var seen []*http.Request
		recording := func(outreq *http.Request, value string, escape bool) string {
			seen = append(seen, outreq)
			return testHeaderVariableReplacer(outreq, value, escape)
		}

		newModifier(request, http.Header{}, recording)(http.Header{"X-Api-Key": {"$tyk_context.caller"}})

		require.Len(t, seen, 1)
		assert.Same(t, request, seen[0], "the modifier has to resolve against the request it was built for")
	})

	t.Run("two modifiers resolve to their own caller", func(t *testing.T) {
		// The modifier is built per request, so the value of one caller must not reach the
		// other. This is the unit level shape of the credential isolation tests.
		for _, caller := range []string{"caller-a", "caller-b"} {
			header := http.Header{}
			additional := http.Header{"X-Upstream-Authorization": {"Bearer $tyk_context.caller"}}

			newModifier(newHeaderModifierRequest(caller), additional, testHeaderVariableReplacer)(header)

			assert.Equal(t, "Bearer "+caller, header.Get("X-Upstream-Authorization"))
		}
	})
}

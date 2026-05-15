package enginev3

import (
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/tyk/apidef"
)

// TestGraphqlDataSourceWebSocketProtocol_V3DefaultFlip pins the V3 default
// subprotocol behaviour for upstream GraphQL data sources. V3 (Preview)
// flips the default from the legacy `graphql-ws` to the modern
// `graphql-transport-ws` (Apollo Router's default). Explicit values
// configured via `subscription_type` continue to be respected verbatim.
//
// This is the load-bearing assertion of Task 3 — captured here as a unit
// test rather than only as a side-effect of the gateway smoke test, so
// it remains stable and meaningful even when the upstream subscription
// dial path can't be exercised end-to-end (see the package-level note in
// gateway/mw_graphql_test.go::TestGraphQLMiddleware_V3_Subscription_GraphQLUpstream_TWS
// for the upstream graphql-go-tools v2 lifetime issue).
func TestGraphqlDataSourceWebSocketProtocol_V3DefaultFlip(t *testing.T) {
	cases := []struct {
		name     string
		input    apidef.SubscriptionType
		expected string
	}{
		{
			name:     "unset defaults to graphql-transport-ws (V3 flip)",
			input:    "",
			expected: graphqldatasource.ProtocolGraphQLTWS,
		},
		{
			name:     "explicit graphql-ws is respected",
			input:    apidef.GQLSubscriptionWS,
			expected: graphqldatasource.ProtocolGraphQLWS,
		},
		{
			name:     "explicit graphql-transport-ws is respected",
			input:    apidef.GQLSubscriptionTransportWS,
			expected: graphqldatasource.ProtocolGraphQLTWS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := graphqlDataSourceWebSocketProtocol(tc.input)
			if got != tc.expected {
				t.Fatalf("graphqlDataSourceWebSocketProtocol(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

//go:build ee || dev

package enginev3

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUniversalDataGraph_FederationSubgraph(t *testing.T) {
	schema := `
		type Query {
			me: User
		}
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
	`

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: schema,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{},
				DataSources:  []apidef.GraphQLEngineDataSource{},
			},
		},
	}

	udg := &UniversalDataGraph{
		ApiDefinition: apiDef,
	}

	conf, err := udg.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, conf)

	hasEntitiesDS := false
	hasServiceDS := false
	for _, ds := range conf.DataSources() {
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName == "Query" {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "_entities" {
						hasEntitiesDS = true
					}
					if fieldName == "_service" {
						hasServiceDS = true
					}
				}
			}
		}
	}

	assert.True(t, hasEntitiesDS, "Should have _entities data source")
	assert.True(t, hasServiceDS, "Should have _service data source")
}

// TestPickLookupField_SkipsListReturningFields guards the bug where a Query
// field returning `[User]` would unwrap to the named type `User` and become
// a candidate for the auto-detected entity lookup. The resolver expects a
// single object, not a list, so list-returning fields must be filtered out
// before candidate selection.
func TestPickLookupField_SkipsListReturningFields(t *testing.T) {
	listResult := introspectionTypeRef{
		Kind: "NON_NULL",
		OfType: &introspectionTypeRef{
			Kind: "LIST",
			OfType: &introspectionTypeRef{
				Kind:   "NON_NULL",
				OfType: &introspectionTypeRef{Kind: "OBJECT", Name: "User"},
			},
		},
	}
	objectResult := introspectionTypeRef{Kind: "OBJECT", Name: "User"}
	idArg := introspectionTypeRef{
		Kind:   "NON_NULL",
		OfType: &introspectionTypeRef{Kind: "SCALAR", Name: "ID"},
	}

	intro := &introspectionResult{
		queryTypeName: "Query",
		queryFields: []introspectionField{
			{
				Name:       "users",
				ReturnType: listResult,
				Args:       []introspectionArg{{Name: "id", Type: idArg}},
			},
			{
				Name:       "user",
				ReturnType: objectResult,
				Args:       []introspectionArg{{Name: "id", Type: idArg}},
			},
		},
	}

	field, argName, _, err := pickLookupField(intro, "User", "id")
	require.NoError(t, err)
	assert.Equal(t, "user", field, "must pick the singular `user` field, not list-returning `users`")
	assert.Equal(t, "id", argName)
}

// TestPickLookupField_AllListsIsNoMatch ensures we report a clean
// "no Query field" error when every candidate returns a list — there is no
// valid auto-detected lookup in that case.
func TestPickLookupField_AllListsIsNoMatch(t *testing.T) {
	listResult := introspectionTypeRef{
		Kind:   "LIST",
		OfType: &introspectionTypeRef{Kind: "OBJECT", Name: "User"},
	}
	intro := &introspectionResult{
		queryTypeName: "Query",
		queryFields: []introspectionField{
			{
				Name:       "users",
				ReturnType: listResult,
				Args: []introspectionArg{{
					Name: "id",
					Type: introspectionTypeRef{Kind: "SCALAR", Name: "ID"},
				}},
			},
		},
	}

	_, _, _, err := pickLookupField(intro, "User", "id")
	require.Error(t, err)
}

// TestServiceSDL_PreservesExplicitLinkDirective verifies that when the
// customer's SDL already declares a federation version through `@link` —
// here the v1 URL — the SDL emitted by `_service { sdl }` keeps that link.
// The v2 link directive must NOT be prepended on top of an explicit v1
// declaration. Orphan Query stripping still applies to federation SDLs, so
// we register `Query.user` here to keep it in the output.
func TestServiceSDL_PreservesExplicitLinkDirective(t *testing.T) {
	customerSDL := `extend schema @link(url: "https://specs.apollo.dev/federation/v1.0")
type User @key(fields: "id") {
  id: ID!
  username: String!
}
type Query {
  user(id: ID!): User
}
`
	dataSources := []apidef.GraphQLEngineDataSource{{
		RootFields: []apidef.GraphQLTypeFields{
			{Type: "Query", Fields: []string{"user"}},
			{Type: "User", Fields: []string{"id", "username"}},
		},
	}}
	out := serviceSDL(customerSDL, dataSources)
	assert.Contains(t, out, `@link(url: "https://specs.apollo.dev/federation/v1.0")`, "explicit v1 @link must be preserved")
	assert.NotContains(t, out, "v2.5", "must not prepend v2 link when v1 is declared")
	assert.Contains(t, out, `user(id: ID!): User`, "registered Query field must remain")
	assert.Contains(t, out, `type User @key(fields: "id")`, "customer SDL body must be preserved")
}

// TestServiceSDL_AutoPrependsV2LinkWhenAbsent verifies that a customer SDL
// with `@key` but no `@link` gains a v2 federation `@link` directive in the
// SDL emitted by `_service { sdl }`. This is the path that makes Apollo
// Rover and Apollo Router classify Tyk as a federation v2 subgraph.
func TestServiceSDL_AutoPrependsV2LinkWhenAbsent(t *testing.T) {
	customerSDL := `type User @key(fields: "id") {
  id: ID!
  username: String!
}
type Query {
  user(id: ID!): User
}
`
	dataSources := []apidef.GraphQLEngineDataSource{{
		RootFields: []apidef.GraphQLTypeFields{
			{Type: "Query", Fields: []string{"user"}},
			{Type: "User", Fields: []string{"id", "username"}},
		},
	}}
	out := serviceSDL(customerSDL, dataSources)
	assert.Contains(t, out, `@link(url: "https://specs.apollo.dev/federation/v2.5"`, "must auto-prepend the v2 link")
	assert.Contains(t, out, `import: ["@key"`, "must import federation v2 directives")
	assert.Contains(t, out, `type User @key(fields: "id")`, "customer SDL body must be preserved")
}

// TestServiceSDL_NoChangeWhenNoKeyDirective verifies that a plain GraphQL
// API (no `@key`, no `@link`) is left untouched. We only augment SDLs that
// look federation-shaped — non-federation APIs continue to emit the
// customer's SDL verbatim and Query fields are NOT stripped.
func TestServiceSDL_NoChangeWhenNoKeyDirective(t *testing.T) {
	customerSDL := `type User {
  id: ID!
  username: String!
}
type Query {
  user(id: ID!): User
}
`
	out := serviceSDL(customerSDL, nil)
	assert.Equal(t, customerSDL, out, "plain GraphQL APIs must pass through unchanged")
	assert.NotContains(t, out, "@link", "must not add @link to non-federation SDL")
}

// TestServiceSDL_StripsOrphanQueryField verifies that Query fields not backed
// by any data source are stripped from the SDL emitted by `_service { sdl }`
// for federation subgraphs. Without this, Apollo Router routes queries
// against `Query.user(id)` to Tyk, where the UDG planner has no data source
// for that field and returns "Failed to fetch from Subgraph at path
// 'query.user'". Direct `_entities` resolution still works (entity types and
// their fields are unchanged).
func TestServiceSDL_StripsOrphanQueryField(t *testing.T) {
	customerSDL := `type User @key(fields: "id") {
  id: ID!
  username: String!
}
type Query {
  user(id: ID!): User
  health: String
}
`
	// Only the User entity's fields are registered — no Query data source.
	dataSources := []apidef.GraphQLEngineDataSource{{
		RootFields: []apidef.GraphQLTypeFields{
			{Type: "User", Fields: []string{"id", "username"}},
		},
	}}
	out := serviceSDL(customerSDL, dataSources)
	assert.NotContains(t, out, "user(id:", "orphan Query.user field must be stripped")
	assert.NotContains(t, out, "health:", "orphan Query.health field must be stripped")
	assert.Contains(t, out, `type User @key(fields: "id")`, "User entity must remain")
	assert.Contains(t, out, "id: ID!", "User entity fields must remain")
	assert.Contains(t, out, "username: String!", "User entity fields must remain")
}

// TestServiceSDL_KeepsRegisteredQueryField is the positive counterpart to
// TestServiceSDL_StripsOrphanQueryField: when a data source DOES register a
// Query field, that field is kept in the SDL while other (orphan) fields are
// still stripped.
func TestServiceSDL_KeepsRegisteredQueryField(t *testing.T) {
	customerSDL := `type User @key(fields: "id") {
  id: ID!
  username: String!
}
type Query {
  user(id: ID!): User
  health: String
}
`
	dataSources := []apidef.GraphQLEngineDataSource{{
		RootFields: []apidef.GraphQLTypeFields{
			{Type: "Query", Fields: []string{"user"}},
			{Type: "User", Fields: []string{"id", "username"}},
		},
	}}
	out := serviceSDL(customerSDL, dataSources)
	assert.Contains(t, out, "user(id: ID!): User", "registered Query.user must remain")
	assert.NotContains(t, out, "health:", "orphan Query.health must still be stripped")
}

// TestServiceSDL_NoStripWhenNotFederated guards against accidental stripping
// of plain (non-federation) GraphQL APIs. Without `@key` and without `@link`,
// the schema is not a federation subgraph, so all Query fields must remain
// regardless of data-source registration.
func TestServiceSDL_NoStripWhenNotFederated(t *testing.T) {
	customerSDL := `type Query {
  hello: String
}
`
	// No data sources registered at all — but the schema isn't federation-shaped.
	out := serviceSDL(customerSDL, nil)
	assert.Equal(t, customerSDL, out, "plain GraphQL SDL must pass through unchanged")
	assert.Contains(t, out, "hello: String", "plain Query fields must not be stripped")
}

// TestUDGFederation_Subscription_PlanShape is a sanity check on the engine
// configuration produced for a UDG API that mixes federation (`@key`) with a
// Subscription type. It verifies three properties of the plan shape:
//
//  1. The user GraphQL data source carries a Subscription RootNode for the
//     subscription field — without this the planner has no source for the
//     operation.
//  2. The federation-internal entities data source (responsible for
//     `_entities`) does NOT have any Subscription-typed RootNode. Apollo
//     Federation never dispatches subscriptions to `_entities`, and the
//     planner must not be allowed to think it can.
//  3. The User entity remains wired as an entity — the federation
//     `_Entity` union and `_entities` Query field appear on the federated
//     schema, proving Subscription-on-an-entity-type didn't break the
//     existing federation path.
//
// This is the unit-level guard for the federation+subscription happy path
// that the gateway-level tests
// (`TestGraphQLMiddleware_V3_Subscription_FederationSubgraph_TWS`) cover
// end-to-end.
func TestUDGFederation_Subscription_PlanShape(t *testing.T) {
	schema := `
		type Query { user(id: ID!): User }
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
		type Subscription { onUser: User! }
	`

	// buildEntityResolvers probes the configured upstream for `_service
	// { sdl }`. Stand up a minimal mock that answers with a federation-v2
	// SDL so the resolver-builder picks the federation-passthrough
	// strategy and the engine config can be assembled without a real
	// upstream.
	upstreamSDL := `extend schema @link(url: "https://specs.apollo.dev/federation/v2.5", import: ["@key"])
type User @key(fields: "id") {
  id: ID!
  username: String!
}
`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
	}))
	defer upstream.Close()

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: schema,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{},
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
						Name: "users_ds",
						RootFields: []apidef.GraphQLTypeFields{
							{Type: "Query", Fields: []string{"user"}},
							{Type: "Subscription", Fields: []string{"onUser"}},
							{Type: "User", Fields: []string{"id", "username"}},
						},
						Config: []byte(fmt.Sprintf(`{"url":%q,"method":"POST"}`, upstream.URL)),
					},
				},
			},
		},
	}

	udg := &UniversalDataGraph{
		ApiDefinition:             apiDef,
		subscriptionClientFactory: &MockSubscriptionClientFactory{},
	}

	conf, err := udg.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, conf)

	// Walk the configured data sources to classify them. The user
	// GraphQL data source is identified by its registered Subscription
	// RootNode; the federation-internal entities DS is identified by
	// having `_entities` as a Query RootNode.
	var (
		userDSHasSubscription     bool
		entitiesDSSawSubscription bool
		hasEntitiesDS             bool
		hasUserEntityRoot         bool
	)
	for _, ds := range conf.DataSources() {
		dsHasEntities := false
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName == "Query" {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "_entities" {
						dsHasEntities = true
						hasEntitiesDS = true
					}
				}
			}
			if rootNode.TypeName == "User" {
				hasUserEntityRoot = true
			}
		}
		// Now check Subscription RootNodes on this DS.
		for _, rootNode := range ds.RootNodes {
			if rootNode.TypeName != "Subscription" {
				continue
			}
			if dsHasEntities {
				entitiesDSSawSubscription = true
			} else {
				for _, fieldName := range rootNode.FieldNames {
					if fieldName == "onUser" {
						userDSHasSubscription = true
					}
				}
			}
		}
	}

	assert.True(t, userDSHasSubscription,
		"user GraphQL data source must register Subscription.onUser as a RootNode")
	assert.False(t, entitiesDSSawSubscription,
		"entities data source must NOT advertise any Subscription RootNode")
	assert.True(t, hasEntitiesDS,
		"federation _entities Query data source must still be present on a federation+subscription API")
	assert.True(t, hasUserEntityRoot,
		"User entity RootNode must remain wired on the user data source")

	// Planner-level smoke check: the entities-DS planner's
	// ConfigureSubscription must return an empty SubscriptionConfiguration.
	// This pins the documented contract in entities_datasource.go and
	// guards against an accidental flip if a future refactor moves
	// subscription wiring around.
	planner := &entitiesDataSourcePlanner{}
	subCfg := planner.ConfigureSubscription()
	assert.Empty(t, subCfg.Input,
		"entitiesDataSourcePlanner.ConfigureSubscription must return zero SubscriptionConfiguration")
}

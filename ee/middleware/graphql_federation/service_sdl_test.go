package graphql_federation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

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

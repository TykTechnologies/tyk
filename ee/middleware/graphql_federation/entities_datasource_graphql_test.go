package graphql_federation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

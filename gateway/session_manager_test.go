package gateway

import (
	"testing"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/v3/user"
)

func TestSessionLimiter_DepthLimitEnabled(t *testing.T) {
	l := SessionLimiter{}

	accessDefPerField := &user.AccessDefinition{
		FieldAccessRights: []user.FieldAccessDefinition{
			{TypeName: "Query", FieldName: "countries", Limits: user.FieldLimits{MaxQueryDepth: 0}},
			{TypeName: "Query", FieldName: "continents", Limits: user.FieldLimits{MaxQueryDepth: -1}},
			{TypeName: "Mutation", FieldName: "putCountry", Limits: user.FieldLimits{MaxQueryDepth: 2}},
		},
		Limit: &user.APILimit{
			MaxQueryDepth: 0,
		},
	}

	accessDefWithGlobal := &user.AccessDefinition{
		Limit: &user.APILimit{
			MaxQueryDepth: 2,
		},
	}

	t.Run("graphqlEnabled", func(t *testing.T) {
		assert.False(t, l.DepthLimitEnabled(false, accessDefWithGlobal))
		assert.True(t, l.DepthLimitEnabled(true, accessDefWithGlobal))
	})

	t.Run("Per field", func(t *testing.T) {
		assert.True(t, l.DepthLimitEnabled(true, accessDefPerField))
		accessDefPerField.FieldAccessRights = []user.FieldAccessDefinition{}
		assert.False(t, l.DepthLimitEnabled(true, accessDefPerField))
	})

	t.Run("Global", func(t *testing.T) {
		assert.True(t, l.DepthLimitEnabled(true, accessDefWithGlobal))
		accessDefWithGlobal.Limit.MaxQueryDepth = 0
		assert.False(t, l.DepthLimitEnabled(true, accessDefWithGlobal))
	})
}

func TestSessionLimiter_DepthLimitExceeded(t *testing.T) {
	l := SessionLimiter{}
	countriesSchema, err := graphql.NewSchemaFromString(gqlCountriesSchema)
	require.NoError(t, err)

	req := &graphql.Request{
		OperationName: "TestQuery",
		Variables:     nil,
		Query:         "query TestQuery { countries { code name continent { code name countries { code name } } } }",
	}

	accessDef := &user.AccessDefinition{
		Limit: &user.APILimit{
			MaxQueryDepth: 3,
		},
		FieldAccessRights: []user.FieldAccessDefinition{},
	}

	t.Run("should fallback to global limit and exceed", func(t *testing.T) {
		failReason := l.DepthLimitExceeded(req, accessDef, countriesSchema)
		assert.Equal(t, sessionFailDepthLimit, failReason)
	})

	t.Run("should respect unlimited specific field depth limit and not exceed", func(t *testing.T) {
		accessDef.FieldAccessRights = []user.FieldAccessDefinition{
			{
				TypeName:  "Query",
				FieldName: "countries",
				Limits: user.FieldLimits{
					MaxQueryDepth: -1,
				},
			},
		}

		failReason := l.DepthLimitExceeded(req, accessDef, countriesSchema)
		assert.Equal(t, sessionFailNone, failReason)
	})

	t.Run("should respect higher specific field depth limit and not exceed", func(t *testing.T) {
		accessDef.FieldAccessRights = []user.FieldAccessDefinition{
			{
				TypeName:  "Query",
				FieldName: "countries",
				Limits: user.FieldLimits{
					MaxQueryDepth: 10,
				},
			},
		}

		failReason := l.DepthLimitExceeded(req, accessDef, countriesSchema)
		assert.Equal(t, sessionFailNone, failReason)
	})

	t.Run("should respect lower specific field depth limit and exceed", func(t *testing.T) {
		accessDef.Limit.MaxQueryDepth = 100
		accessDef.FieldAccessRights = []user.FieldAccessDefinition{
			{
				TypeName:  "Query",
				FieldName: "countries",
				Limits: user.FieldLimits{
					MaxQueryDepth: 1,
				},
			},
		}

		failReason := l.DepthLimitExceeded(req, accessDef, countriesSchema)
		assert.Equal(t, sessionFailDepthLimit, failReason)
	})

}

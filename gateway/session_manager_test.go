package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
)

func TestSessionLimiter_DepthLimitEnabled(t *testing.T) {
	l := SessionLimiter{}

	accessDefPerField := &user.AccessDefinition{
		FieldAccessRights: []user.FieldAccessDefinition{
			{TypeName: "Query", FieldName: "countries", Limits: user.FieldLimits{MaxQueryDepth: 0}},
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

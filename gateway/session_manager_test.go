package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

func TestGetAccessDefinitionByAPIIDOrSession(t *testing.T) {
	api := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "api",
		},
	}

	t.Run("should return error when api is missing in access rights", func(t *testing.T) {
		sessionWithMissingAPI := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"another-api": {},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithMissingAPI, api)
		assert.Nil(t, accessDef)
		assert.Equal(t, "", allowanceScope)
		assert.Error(t, err)
		assert.Equal(t, "unexpected apiID", err.Error())
	})

	t.Run("should return access definition from session when limits for api are not defined", func(t *testing.T) {
		sessionWithoutAPILimits := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"api": {
					Limit: user.APILimit{},
				},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithoutAPILimits, api)
		assert.Equal(t, &user.AccessDefinition{
			Limit: user.APILimit{
				QuotaMax:           int64(1),
				QuotaRenewalRate:   int64(1),
				QuotaRenews:        int64(1),
				Rate:               1.0,
				Per:                1.0,
				ThrottleInterval:   1.0,
				ThrottleRetryLimit: 1.0,
				MaxQueryDepth:      1.0,
			},
		}, accessDef)
		assert.Equal(t, "", allowanceScope)
		assert.NoError(t, err)
	})

	t.Run("should return access definition with api limits", func(t *testing.T) {
		sessionWithAPILimits := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"api": {
					AllowanceScope: "b",
					FieldAccessRights: []user.FieldAccessDefinition{
						{
							TypeName:  "Query",
							FieldName: "hello",
							Limits: user.FieldLimits{
								MaxQueryDepth: 2,
							},
						},
					},
					Limit: user.APILimit{
						QuotaMax:           int64(2),
						QuotaRenewalRate:   int64(2),
						QuotaRenews:        int64(2),
						Rate:               2.0,
						Per:                2.0,
						ThrottleInterval:   2.0,
						ThrottleRetryLimit: 2.0,
						MaxQueryDepth:      2.0,
					},
				},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithAPILimits, api)
		assert.Equal(t, &user.AccessDefinition{
			FieldAccessRights: []user.FieldAccessDefinition{
				{
					TypeName:  "Query",
					FieldName: "hello",
					Limits: user.FieldLimits{
						MaxQueryDepth: 2,
					},
				},
			},
			Limit: user.APILimit{
				QuotaMax:           int64(2),
				QuotaRenewalRate:   int64(2),
				QuotaRenews:        int64(2),
				Rate:               2.0,
				Per:                2.0,
				ThrottleInterval:   2.0,
				ThrottleRetryLimit: 2.0,
				MaxQueryDepth:      2.0,
			},
		}, accessDef)
		assert.Equal(t, "b", allowanceScope)
		assert.NoError(t, err)
	})
}

package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/storage"

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
				QuotaMax:         int64(1),
				QuotaRenewalRate: int64(1),
				QuotaRenews:      int64(1),
				RateLimit: user.RateLimit{
					Rate: 1.0,
					Per:  1.0,
				},
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
						QuotaMax:         int64(2),
						QuotaRenewalRate: int64(2),
						QuotaRenews:      int64(2),
						RateLimit: user.RateLimit{
							Rate: 2.0,
							Per:  2.0,
						},
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
				QuotaMax:         int64(2),
				QuotaRenewalRate: int64(2),
				QuotaRenews:      int64(2),
				RateLimit: user.RateLimit{
					Rate: 2.0,
					Per:  2.0,
				},
				ThrottleInterval:   2.0,
				ThrottleRetryLimit: 2.0,
				MaxQueryDepth:      2.0,
			},
		}, accessDef)
		assert.Equal(t, "b", allowanceScope)
		assert.NoError(t, err)
	})
}

func TestGetEndpointRateLimitInfo(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		endpoints []user.Endpoint
		expected  *endpointRateLimitInfo
		found     bool
	}{
		{
			name:   "Matching endpoint and method",
			method: http.MethodGet,
			path:   "/api/v1/users",
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.EndpointMethodRateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: &endpointRateLimitInfo{
				keySuffix: storage.HashStr("GET:/api/v1/users"),
				rate:      100,
				per:       60,
			},
			found: true,
		},
		{
			name:   "Matching endpoint, non-matching method",
			path:   "/api/v1/users",
			method: http.MethodPost,
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.EndpointMethodRateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
		{
			name:   "Non-matching endpoint",
			method: http.MethodGet,
			path:   "/api/v1/products",
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.EndpointMethodRateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
		{
			name:   "Regex path matching",
			path:   "/api/v1/users/123",
			method: http.MethodGet,
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users/[0-9]+",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.EndpointMethodRateLimit{Rate: 50, Per: 30}},
					},
				},
			},
			expected: &endpointRateLimitInfo{
				keySuffix: storage.HashStr("GET:/api/v1/users/[0-9]+"),
				rate:      50,
				per:       30,
			},
			found: true,
		},
		{
			name:   "Invalid regex path",
			path:   "/api/v1/users",
			method: http.MethodGet,
			endpoints: []user.Endpoint{
				{
					Path: "[invalid regex",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.EndpointMethodRateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := getEndpointRateLimitInfo(tt.method, tt.path, tt.endpoints)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, result)
		})
	}
}

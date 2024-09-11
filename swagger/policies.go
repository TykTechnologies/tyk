package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

const (
	PolicyTag     = "Policies"
	PolicyTagDesc = `A Tyk security policy incorporates several security options that can be applied to an API key. It acts as a template that can override individual sections of an API key (or identity) in Tyk.
`
)

func PoliciesApis(r *openapi3.Reflector) error {
	addTag(PolicyTag, PolicyTagDesc, optionalTagParameters{})
	return addOperations(r, getListOfPolicies, getPolicyWithID, updatePolicy, deletePolicyWithID, createPolicy)
}

// Done
func createPolicy(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/policies",
		OperationID: "addPolicy",
		Tag:         PolicyTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetTags(PolicyTag)
	oc.SetSummary("Create a policy.")
	oc.SetDescription("Create a policy in your Tyk Instance.")
	op.StatusInternalServerError("Due to enabled service policy source, please use the Dashboard API.")
	op.StatusBadRequest("Request malformed", func(cu *openapi.ContentUnit) {
		cu.Description = "Malformed request."
	})
	op.AddReqWithSeparateExample(user.Policy{}, minimalPolicies[0])
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5ead7120575961000181867e",
		Status: "ok",
		Action: "added",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Policy created."
	})
	return op.AddOperation()
}

// Done
func getListOfPolicies(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/policies",
		OperationID: "listPolicies",
		Tag:         PolicyTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddRespWithRefExamples(http.StatusOK, new([]user.Policy), []multipleExamplesValues{
		{
			key:         policiesExample,
			httpStatus:  http.StatusOK,
			Summary:     "Example Policies",
			exampleType: Component,
			ref:         policiesExample,
		},
	}, func(cu *openapi.ContentUnit) {
		cu.Description = "List of all policies."
	})
	oc.SetSummary("List policies.")
	oc.SetDescription("Retrieve all the policies in your Tyk instance. Returns an array policies.")
	return op.AddOperation()
}

// Done
func getPolicyWithID(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(
		r, SafeOperation{
			Method:      http.MethodGet,
			PathPattern: "/tyk/policies/{polID}",
			OperationID: "getPolicy",
			Tag:         PolicyTag,
		},
	)
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddResponseWithSeparateExample(new(user.Policy), http.StatusOK, minimalPolicies[0], func(cu *openapi.ContentUnit) {
		cu.Description = "Get details of a single policy."
	})
	oc.SetSummary("Get a policy.")
	oc.SetDescription("You can retrieve details of a single policy by ID in your Tyk instance.")
	op.StatusNotFound("Policy not found", func(cu *openapi.ContentUnit) {
		cu.Description = "Policy not found"
	})
	op.AddPathParameter("polID", "You can retrieve details of a single policy by ID in your Tyk instance.", OptionalParameterValues{
		Example: valueToInterface("5ead7120575961000181867e"),
	})
	return op.AddOperation()
}

// Done
func deletePolicyWithID(r *openapi3.Reflector) error {
	// TODO:: we return error 500 instead of 404 if policy is not available
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/policies/{polID}",
		OperationID: "deletePolicy",
		Tag:         PolicyTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusInternalServerError("Delete failed")
	op.StatusBadRequest("Must specify an apiID to update", func(cu *openapi.ContentUnit) {
		cu.Description = "Policy Id not provided"
	})
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5ead7120575961000181867e",
		Status: "ok",
		Action: "deleted",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted policy by ID"
	})
	oc.SetSummary("Delete a policy.")
	oc.SetDescription("Delete a policy by ID in your Tyk instance.")
	op.AddPathParameter("polID", "You can retrieve details of a single policy by ID in your Tyk instance.", OptionalParameterValues{
		Example: valueToInterface("5ead7120575961000181867e"),
	})
	return op.AddOperation()
}

func updatePolicy(r *openapi3.Reflector) error {
	// TODO:: Why don't we have error 404
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPut,
		PathPattern: "/tyk/policies/{polID}",
		OperationID: "updatePolicy",
		Tag:         PolicyTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Update a policy.")
	oc.SetDescription("You can update a Policy in your Tyk Instance by ID.")
	op.StatusInternalServerError("Failed to create file!")
	op.AddRespWithExample(apiModifyKeySuccess{
		Key:    "5ead7120575961000181867e",
		Status: "ok",
		Action: "modified",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Policy updated"
	})
	op.StatusBadRequest("Request malformed", func(cu *openapi.ContentUnit) {
		cu.Description = "malformed request"
	})
	op.AddPathParameter("polID", "You can retrieve details of a single policy by ID in your Tyk instance.", OptionalParameterValues{
		Example: valueToInterface("5ead7120575961000181867e"),
	})
	updatePo := minimalPolicies[0]
	updatePo.Name = "update policy sample"
	updatePo.MetaData["update"] = "sample policy update"
	op.AddReqWithSeparateExample(new(user.Policy), updatePo)
	return op.AddOperation()
}

var minimalPolicies = []struct {
	ID                 string                 `json:"id,omitempty"`
	Name               string                 `json:"name"`
	Rate               float64                `json:"rate"`
	Per                float64                `json:"per"`
	QuotaMax           int64                  `json:"quota_max"`
	QuotaRenewalRate   int64                  `json:"quota_renewal_rate"`
	ThrottleInterval   float64                `json:"throttle_interval"`
	ThrottleRetryLimit int                    `json:"throttle_retry_limit"`
	MaxQueryDepth      int                    `json:"max_query_depth"`
	HMACEnabled        bool                   `json:"hmac_enabled"`
	Active             bool                   `json:"active"`
	IsInactive         bool                   `json:"is_inactive"`
	Tags               []string               `json:"tags"`
	KeyExpiresIn       int64                  `json:"key_expires_in"`
	MetaData           map[string]interface{} `json:"meta_data"`
	Partitions         struct {
		ACL        bool `json:"acl"`
		Quota      bool `json:"quota"`
		RateLimit  bool `json:"rate_limit"`
		Complexity bool `json:"complexity"`
		PerAPI     bool `json:"per_api"`
	} `json:"partitions"`
	AccessRights map[string]struct {
		APIName     string   `json:"api_name"`
		APIID       string   `json:"api_id"`
		Versions    []string `json:"versions"`
		AllowedURLs []struct {
			URL     string   `json:"url"`
			Methods []string `json:"methods"`
		} `json:"allowed_urls"`
		DisableIntrospection bool `json:"disable_introspection"`
	} `json:"access_rights"`
}{
	{
		Name:               "Sample policy",
		ID:                 "5ead7120575961000181867e",
		Rate:               1000,
		Per:                60,
		QuotaMax:           10000,
		QuotaRenewalRate:   3600,
		ThrottleInterval:   10,
		ThrottleRetryLimit: 10,
		MaxQueryDepth:      -1,
		HMACEnabled:        false,
		Active:             true,
		IsInactive:         false,
		Tags:               []string{"security"},
		KeyExpiresIn:       2592000,
		MetaData:           map[string]interface{}{"user_type": "mobile_user"},
		Partitions: struct {
			ACL        bool `json:"acl"`
			Quota      bool `json:"quota"`
			RateLimit  bool `json:"rate_limit"`
			Complexity bool `json:"complexity"`
			PerAPI     bool `json:"per_api"`
		}{
			ACL:        true,
			Quota:      true,
			RateLimit:  true,
			Complexity: false,
			PerAPI:     false,
		},
		AccessRights: map[string]struct {
			APIName     string   `json:"api_name"`
			APIID       string   `json:"api_id"`
			Versions    []string `json:"versions"`
			AllowedURLs []struct {
				URL     string   `json:"url"`
				Methods []string `json:"methods"`
			} `json:"allowed_urls"`
			DisableIntrospection bool `json:"disable_introspection"`
		}{
			"itachi-api": {
				APIName:  "Itachi api",
				APIID:    "8ddd91f3cda9453442c477b06c4e2da4",
				Versions: []string{"Default"},
				AllowedURLs: []struct {
					URL     string   `json:"url"`
					Methods []string `json:"methods"`
				}{
					{
						URL:     "/users",
						Methods: []string{"GET"},
					},
				},
				DisableIntrospection: false,
			},
		},
	},
	// You can add more policies here
}

var policies = []*user.Policy{
	{
		ID:                 "5ead7120575961000181867e",
		Name:               "Sample policy",
		OrgID:              "664a14650619d40001f1f00f",
		Rate:               1000,
		Per:                60,
		QuotaMax:           10000,
		QuotaRenewalRate:   3600,
		ThrottleInterval:   10,
		ThrottleRetryLimit: 10,
		MaxQueryDepth:      -1,
		AccessRights: map[string]user.AccessDefinition{
			"8ddd91f3cda9453442c477b06c4e2da4": {
				APIName:  "Itachi api",
				APIID:    "8ddd91f3cda9453442c477b06c4e2da4",
				Versions: []string{"Default"},
				AllowedURLs: []user.AccessSpec{
					{
						URL:     "/users",
						Methods: []string{"GET"},
					},
				},
				RestrictedTypes:      []graphql.Type{},
				AllowedTypes:         []graphql.Type{},
				DisableIntrospection: false,
				Limit: user.APILimit{
					RateLimit: user.RateLimit{
						Smoothing: &apidef.RateLimitSmoothing{
							Enabled:   false,
							Threshold: 500,
							Trigger:   0.8,
							Step:      100,
							Delay:     30,
						},
					},
				},
				FieldAccessRights: []user.FieldAccessDefinition{},
				AllowanceScope:    "",
			},
		},
		HMACEnabled:  false,
		Active:       true,
		IsInactive:   false,
		Tags:         []string{"security"},
		KeyExpiresIn: 2592000,
		Partitions: user.PolicyPartitions{
			Quota:      true,
			RateLimit:  true,
			Complexity: false,
			Acl:        true,
			PerAPI:     false,
		},
		Smoothing: &apidef.RateLimitSmoothing{
			Enabled:   false,
			Threshold: 500,
			Trigger:   0.8,
			Step:      100,
			Delay:     30,
		},
		LastUpdated: "1716980105",
		MetaData: map[string]interface{}{
			"user_type": "mobile_user",
		},
	},
}

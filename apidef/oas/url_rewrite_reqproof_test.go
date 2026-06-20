package oas

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-063
// SW-REQ-063:nominal:nominal
// SW-REQ-063:boundary:nominal
// SW-REQ-063:error_handling:nominal
// SW-REQ-063:error_handling:negative
// SW-REQ-063:determinism:nominal
func TestURLRewritePreservesClassicTriggerShape(t *testing.T) {
	t.Run("input enumeration validates indexes and errors", func(t *testing.T) {
		inputs := []URLRewriteInput{
			InputQuery,
			InputPath,
			InputHeader,
			InputSessionMetadata,
			InputRequestBody,
			InputRequestContext,
		}

		for idx, input := range inputs {
			assert.True(t, input.Valid())
			assert.Equal(t, idx, input.Index())
			assert.NoError(t, input.Err())
		}

		invalid := URLRewriteInput("cookie")
		assert.False(t, invalid.Valid())
		assert.Equal(t, -1, invalid.Index())
		assert.EqualError(t, invalid.Err(), "Invalid value for URL rewrite input: cookie")
	})

	t.Run("fill extract and sort preserve trigger rules", func(t *testing.T) {
		meta := urlRewriteMetaForReqProof()

		var rewrite URLRewrite
		rewrite.Fill(meta)

		assert.True(t, rewrite.Enabled)
		assert.Equal(t, ".*", rewrite.Pattern)
		assert.Equal(t, "https://upstream.example.com/base", rewrite.RewriteTo)
		require.Len(t, rewrite.Triggers, 1)
		assert.Equal(t, ConditionAny, rewrite.Triggers[0].Condition)
		assert.Equal(t, "https://upstream.example.com/rewrite", rewrite.Triggers[0].RewriteTo)
		assert.Equal(t, []*URLRewriteRule{
			{In: InputQuery, Name: "version", Pattern: "v[0-9]+", Negate: true},
			{In: InputPath, Name: "tenant", Pattern: "[a-z]+", Negate: false},
			{In: InputHeader, Name: "Accept", Pattern: "application/json", Negate: false},
			{In: InputHeader, Name: "X-Mode", Pattern: "beta", Negate: true},
			{In: InputSessionMetadata, Name: "role", Pattern: "admin", Negate: false},
			{In: InputRequestBody, Pattern: `"enabled":true`, Negate: false},
			{In: InputRequestContext, Name: "trace", Pattern: "present", Negate: true},
		}, rewrite.Triggers[0].Rules)

		var extracted apidef.URLRewriteMeta
		rewrite.ExtractTo(&extracted)

		assert.False(t, extracted.Disabled)
		assert.Equal(t, meta.MatchPattern, extracted.MatchPattern)
		assert.Equal(t, meta.RewriteTo, extracted.RewriteTo)
		require.Len(t, extracted.Triggers, 1)
		assert.Equal(t, apidef.RoutingTriggerOnType(ConditionAny), extracted.Triggers[0].On)
		assert.Equal(t, "https://upstream.example.com/rewrite", extracted.Triggers[0].RewriteTo)
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "application/json"}, extracted.Triggers[0].Options.HeaderMatches["Accept"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "beta", Reverse: true}, extracted.Triggers[0].Options.HeaderMatches["X-Mode"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "v[0-9]+", Reverse: true}, extracted.Triggers[0].Options.QueryValMatches["version"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "[a-z]+"}, extracted.Triggers[0].Options.PathPartMatches["tenant"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "admin"}, extracted.Triggers[0].Options.SessionMetaMatches["role"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: "present", Reverse: true}, extracted.Triggers[0].Options.RequestContextMatches["trace"])
		assert.Equal(t, apidef.StringRegexMap{MatchPattern: `"enabled":true`}, extracted.Triggers[0].Options.PayloadMatches)

		rewrite.Triggers[0].Rules = []*URLRewriteRule{
			{In: InputRequestContext, Name: "trace"},
			{In: InputHeader, Name: "X-Mode"},
			{In: InputQuery, Name: "version"},
			{In: InputHeader, Name: "Accept"},
		}
		rewrite.Sort()
		assert.Equal(t, []*URLRewriteRule{
			{In: InputQuery, Name: "version"},
			{In: InputHeader, Name: "Accept"},
			{In: InputHeader, Name: "X-Mode"},
			{In: InputRequestContext, Name: "trace"},
		}, rewrite.Triggers[0].Rules)
	})

	t.Run("oas operation hooks fill omit and extract endpoint rewrite metadata", func(t *testing.T) {
		spec := &OAS{T: openapi3.T{Paths: openapi3.NewPaths()}}
		spec.SetTykExtension(&XTykAPIGateway{})
		meta := urlRewriteMetaForReqProof()
		meta.Path = "/pets/{id}"
		meta.Method = http.MethodGet

		spec.fillURLRewrite([]apidef.URLRewriteMeta{
			meta,
			{Path: "/empty", Method: http.MethodPost, Disabled: true},
		})

		operationID := spec.getOperationID("/pets/{id}", http.MethodGet)
		operation := spec.GetTykExtension().Middleware.Operations[operationID]
		require.NotNil(t, operation)
		require.NotNil(t, operation.URLRewrite)
		assert.Equal(t, ".*", operation.URLRewrite.Pattern)
		assert.Equal(t, "https://upstream.example.com/base", operation.URLRewrite.RewriteTo)
		require.Len(t, operation.URLRewrite.Triggers, 1)

		emptyOperationID := spec.getOperationID("/empty", http.MethodPost)
		assert.Nil(t, spec.GetTykExtension().Middleware.Operations[emptyOperationID].URLRewrite)

		var ep apidef.ExtendedPathsSet
		operation.extractURLRewriteTo(&ep, "/pets/{id}", http.MethodGet)
		require.Len(t, ep.URLRewrite, 1)
		assert.Equal(t, "/pets/{id}", ep.URLRewrite[0].Path)
		assert.Equal(t, http.MethodGet, ep.URLRewrite[0].Method)
		assert.False(t, ep.URLRewrite[0].Disabled)
		assert.Equal(t, ".*", ep.URLRewrite[0].MatchPattern)

		var emptyOperation Operation
		emptyOperation.extractURLRewriteTo(&ep, "/skip", http.MethodDelete)
		assert.Len(t, ep.URLRewrite, 1)
	})

	t.Run("repeated fill is deterministic", func(t *testing.T) {
		meta := urlRewriteMetaForReqProof()

		var first URLRewrite
		var second URLRewrite
		first.Fill(meta)
		second.Fill(meta)

		assert.Equal(t, first, second)
	})
}

func urlRewriteMetaForReqProof() apidef.URLRewriteMeta {
	options := apidef.NewRoutingTriggerOptions()
	options.HeaderMatches["X-Mode"] = apidef.StringRegexMap{MatchPattern: "beta", Reverse: true}
	options.HeaderMatches["Accept"] = apidef.StringRegexMap{MatchPattern: "application/json"}
	options.QueryValMatches["version"] = apidef.StringRegexMap{MatchPattern: "v[0-9]+", Reverse: true}
	options.PathPartMatches["tenant"] = apidef.StringRegexMap{MatchPattern: "[a-z]+"}
	options.SessionMetaMatches["role"] = apidef.StringRegexMap{MatchPattern: "admin"}
	options.RequestContextMatches["trace"] = apidef.StringRegexMap{MatchPattern: "present", Reverse: true}
	options.PayloadMatches = apidef.StringRegexMap{MatchPattern: `"enabled":true`}

	return apidef.URLRewriteMeta{
		MatchPattern: ".*",
		RewriteTo:    "https://upstream.example.com/base",
		Triggers: []apidef.RoutingTrigger{
			{
				On:        apidef.RoutingTriggerOnType(ConditionAll),
				Options:   apidef.NewRoutingTriggerOptions(),
				RewriteTo: "https://upstream.example.com/ignored",
			},
			{
				On:        apidef.RoutingTriggerOnType(ConditionAny),
				Options:   options,
				RewriteTo: "https://upstream.example.com/rewrite",
			},
		},
	}
}

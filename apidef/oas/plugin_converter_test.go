package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)


func TestTykAPIDefinitionToSwagger(t *testing.T) {
	tReqHeaders := []apidef.HeaderInjectionMeta{
		{
			Method:        "get",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-req-header": "add-req-header-val"},
			DeleteHeaders: []string{"del-req-header"},
		},
		{
			Method:        "post",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-req-header2": "add-req-header-val2"},
			DeleteHeaders: []string{"del-req-header2"},
		},
		{
			Method:        "get",
			Path:          "/headers",
			AddHeaders:    map[string]string{"add-req-header3": "add-req-header-val3"},
			DeleteHeaders: []string{"del-req-header3"},
		},
	}

	tResHeaders := []apidef.HeaderInjectionMeta{
		{
			Method:        "get",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-res-header": "add-res-header-val"},
			DeleteHeaders: []string{"del-res-header"},
		},
		{
			Method:        "post",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-res-header2": "add-res-header-val2"},
			DeleteHeaders: []string{"del-req-header2"},
		},
		{
			Method:        "get",
			Path:          "/headers",
			AddHeaders:    map[string]string{"add-res-header3": "add-res-header-val3"},
			DeleteHeaders: []string{"del-res-header3"},
		},
	}

	whites := []apidef.EndPointMeta{{
		Path:       "/ip",
		IgnoreCase: true,
		MethodActions: map[string]apidef.EndpointMethodMeta{
			"GET": {
				Action: apidef.Reply,
				Code:   http.StatusCreated,
				Data:   "mock body",
				Headers: map[string]string{
					"mock-header": "mock-header-val",
				},
			},
			"HEAD": {
				Action: apidef.NoAction,
				Code:   http.StatusCreated,
				Data:   "mock body",
				Headers: map[string]string{
					"mock-header": "mock-header-val",
				},
			},
			"POST": {
				Action: apidef.Reply,
				Code:   http.StatusBadGateway,
				Data:   "post mock body",
				Headers: map[string]string{
					"post-mock-header": "post-mock-header-val",
				},
			},
		},
	},
	}

	api := apidef.APIDefinition{}
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {
			ExtendedPaths: apidef.ExtendedPathsSet{
				TransformHeader:         tReqHeaders,
				TransformResponseHeader: tResHeaders,
				WhiteList:               whites,
			},
		},
	}
}

func TestPluginConverter_TransformHeadersToOAS(t *testing.T) {
	tReqHeaders := []apidef.HeaderInjectionMeta{
		{
			Method:        "get",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-req-header": "add-req-header-val"},
			DeleteHeaders: []string{"del-req-header"},
		},
		{
			Method:        "post",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-req-header2": "add-req-header-val2"},
			DeleteHeaders: []string{"del-req-header2"},
		},
		{
			Method:        "get",
			Path:          "/headers",
			AddHeaders:    map[string]string{"add-req-header3": "add-req-header-val3"},
			DeleteHeaders: []string{"del-req-header3"},
		},
	}

	tResHeaders := []apidef.HeaderInjectionMeta{
		{
			Method:        "get",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-res-header": "add-res-header-val"},
			DeleteHeaders: []string{"del-res-header"},
		},
		{
			Method:        "post",
			Path:          "/ip",
			AddHeaders:    map[string]string{"add-res-header2": "add-res-header-val2"},
			DeleteHeaders: []string{"del-res-header2"},
		},
		{
			Method:        "get",
			Path:          "/headers",
			AddHeaders:    map[string]string{"add-res-header3": "add-res-header-val3"},
			DeleteHeaders: []string{"del-res-header3"},
		},
	}

	thConverter := TransformHeadersConverter{}
	swaggerPaths := make(openapi3.Paths)
	thConverter.AppendToSwagger(swaggerPaths, tReqHeaders, tResHeaders)

	var resTReqHeaders, resTResHeaders []apidef.HeaderInjectionMeta

	for swaggerPath, swaggerPathItem := range swaggerPaths {
		for method, operation := range swaggerPathItem.Operations() {
			resTReqHeaders, resTResHeaders = thConverter.AppendToTyk(resTReqHeaders, resTResHeaders, swaggerPath, method, operation.Extensions["x-tyk-plugins"].(*XTykPlugins).TransformHeaders)
		}
	}

	assert.Equal(t, tReqHeaders, resTReqHeaders)
	assert.Equal(t, tResHeaders, resTResHeaders)
}

func TestEndpointMetasConverter_ToSwagger(t *testing.T) {
	whites := []apidef.EndPointMeta{{
		Path:       "/ip",
		IgnoreCase: true,
		MethodActions: map[string]apidef.EndpointMethodMeta{
			"GET": {
				Action: apidef.Reply,
				Code:   http.StatusCreated,
				Data:   "mock body",
				Headers: map[string]string{
					"mock-header": "mock-header-val",
				},
			},
			"HEAD": {
				Action: apidef.NoAction,
				Code:   http.StatusCreated,
				Data:   "mock body",
				Headers: map[string]string{
					"mock-header": "mock-header-val",
				},
			},
			"POST": {
				Action: apidef.Reply,
				Code:   http.StatusBadGateway,
				Data:   "post mock body",
				Headers: map[string]string{
					"post-mock-header": "post-mock-header-val",
				},
			},
		},
	},
	}

	c := EndpointMetasConverter{}
	swaggerPaths := make(openapi3.Paths)
	c.AppendToSwagger(swaggerPaths, whites, whiteList)

	var resWhiteList []apidef.EndPointMeta

	for swaggerPath, swaggerPathItem := range swaggerPaths {
		for method, operation := range swaggerPathItem.Operations() {
			resWhiteList = c.AppendToTyk(resWhiteList, swaggerPath, method, operation.Extensions["x-tyk-plugins"].(*XTykPlugins).Allowed, operation.Extensions["x-tyk-plugins"].(*XTykPlugins).Mock)
		}
	}

	assert.Equal(t, whites, resWhiteList)
}

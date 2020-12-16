package oas

import (
	"encoding/json"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

type Converter struct {
	transformHeaders TransformHeadersConverter
	endpointMetas    EndpointMetasConverter
	authToken        AuthTokenConverter
	jwt              JWTConverter
	root             RootConverter
}

func (c Converter) TykAPIDefinitionToSwagger(api apidef.APIDefinition, swagger *openapi3.Swagger, version string) {
	swagger.Paths = make(openapi3.Paths)
	tykPaths := api.VersionData.Versions[version].ExtendedPaths

	c.transformHeaders.AppendToSwagger(swagger.Paths, tykPaths.TransformHeader, tykPaths.TransformResponseHeader)
	c.endpointMetas.AppendToSwagger(swagger.Paths, tykPaths.WhiteList, whiteList)
	c.endpointMetas.AppendToSwagger(swagger.Paths, tykPaths.BlackList, blackList)
	c.endpointMetas.AppendToSwagger(swagger.Paths, tykPaths.Ignored, ignored)

	c.authToken.ConvertToSwagger(api, &swagger.Components)
	c.root.ConvertToOAS(api, swagger)

	if api.UseStandardAuth {
		swagger.Security.With(openapi3.SecurityRequirement{"token": []string{}})
	}

	//c.jwt.AppendToSwagger()

	return
}

func (c Converter) SwaggerToTykAPIDefinition(swagger openapi3.Swagger, version string) (api apidef.APIDefinition) {
	var tykPaths apidef.ExtendedPathsSet

	for swaggerPath, swaggerPathItem := range swagger.Paths {
		for method, operation := range swaggerPathItem.Operations() {
			if operation.Extensions == nil {
				continue
			}

			intOperation, ok := operation.Extensions["x-tyk-plugins"]
			if !ok {
				continue
			}

			var xTykPlugins *XTykPlugins
			if xTykPlugins, ok = intOperation.(*XTykPlugins); !ok {
				rawOperation := intOperation.(json.RawMessage)
				_ = json.Unmarshal(rawOperation, &xTykPlugins)
			}

			tykPaths.TransformHeader, tykPaths.TransformResponseHeader = c.transformHeaders.AppendToTyk(tykPaths.TransformHeader, tykPaths.TransformResponseHeader, swaggerPath, method, xTykPlugins.TransformHeaders)
			tykPaths.WhiteList = c.endpointMetas.AppendToTyk(tykPaths.WhiteList, swaggerPath, method, xTykPlugins.Allowed, xTykPlugins.Mock)
			tykPaths.BlackList = c.endpointMetas.AppendToTyk(tykPaths.BlackList, swaggerPath, method, xTykPlugins.Blocked, xTykPlugins.Mock)
			tykPaths.Ignored = c.endpointMetas.AppendToTyk(tykPaths.Ignored, swaggerPath, method, xTykPlugins.IgnoreAuthentication, xTykPlugins.Mock)
		}
	}

	c.authToken.ConvertToTykAPIDefinition(swagger.Components, &api)
	c.root.ConvertToTyk(swagger, &api)

	for _, sr := range swagger.Security {
		for authType, _ := range sr {
			if authType == "token" {
				api.UseStandardAuth = true
			}
		}
	}

	api.VersionData.Versions = map[string]apidef.VersionInfo{
		version: {
			UseExtendedPaths: true,
			ExtendedPaths:    tykPaths,
		},
	}

	return
}

type EndpointMetaType int

const (
	whiteList EndpointMetaType = 0
	blackList EndpointMetaType = 1
	ignored   EndpointMetaType = 2
)

type RootConverter struct {
}

func (c RootConverter) ConvertToOAS(api apidef.APIDefinition, oas *openapi3.Swagger) {
	if oas.Extensions == nil {
		oas.Extensions = make(map[string]interface{})
	}

	if oas.Info == nil {
		oas.Info = &openapi3.Info{}
	}

	oas.Info.Title = api.Name

	xTykConfig := &XTykConfig{
		APIID:    api.APIID,
		Active:   api.Active,
		Internal: api.Internal,
		Proxy: &Proxy{
			TargetURL: api.Proxy.TargetURL,
			ListenPath: &ListenPath{
				URL:   api.Proxy.ListenPath,
				Strip: api.Proxy.StripListenPath,
			},
		},
	}

	authSettings := &AuthSettings{
		StripAuthData: api.StripAuthData,
	}

	if (*authSettings != AuthSettings{}) {
		xTykConfig.AuthSettings = authSettings
	}

	oas.ExtensionProps.Extensions["x-tyk-config"] = xTykConfig
}

func (c RootConverter) ConvertToTyk(oas openapi3.Swagger, api *apidef.APIDefinition) {
	if info := oas.Info; info != nil {
		api.Name = info.Title
	}

	var xTykConfig *XTykConfig

	intXTykConfig, ok := oas.Extensions["x-tyk-config"]
	if !ok {
		return
	}

	xTykConfig, ok = intXTykConfig.(*XTykConfig)
	if !ok {
		rawXTykConfig, ok := intXTykConfig.(json.RawMessage);
		if !ok {
			return
		}
		_ = json.Unmarshal(rawXTykConfig, &xTykConfig)
	}

	api.APIID = xTykConfig.APIID
	api.Active = xTykConfig.Active
	api.Internal = xTykConfig.Internal

	// Proxy
	if proxy := xTykConfig.Proxy; proxy != nil {
		api.Proxy.TargetURL = proxy.TargetURL
		api.Proxy.ListenPath = proxy.ListenPath.URL
		if listenPath := proxy.ListenPath; listenPath != nil {
			api.Proxy.StripListenPath = listenPath.Strip
			api.Proxy.ListenPath = listenPath.URL
		}
	}

	// AuthSettings
	if authSettings := xTykConfig.AuthSettings; authSettings != nil {
		api.StripAuthData = authSettings.StripAuthData
	}
}

type XTykConfig struct {
	APIID        string        `bson:"api-id" json:"api-id,omitempty"`
	Active       bool          `bson:"active,omitempty" json:"active,omitempty"`
	Internal     bool          `bson:"internal,omitempty" json:"internal,omitempty"`
	Proxy        *Proxy        `bson:"proxy,omitempty" json:"proxy,omitempty"`
	AuthSettings *AuthSettings `bson:"auth-settings,omitempty" json:"auth-settings,omitempty"`
}

type Proxy struct {
	TargetURL  string      `bson:"target-url,omitempty" json:"target-url,omitempty"`
	ListenPath *ListenPath `bson:"listen-path,omitempty" json:"listen-path,omitempty"`
}

type ListenPath struct {
	URL   string `bson:"url,omitempty" json:"url,omitempty"`
	Strip bool   `bson:"strip,omitempty" json:"strip,omitempty"`
}

type AuthSettings struct {
	StripAuthData bool `bson:"strip-auth-data,omitempty" json:"strip-auth-data,omitempty"`
}

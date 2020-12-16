package oas

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/ghodss/yaml"
	"testing"
)

func TestTokenConverter_ConvertToSwagger(t *testing.T) {
	tokenConverter := AuthTokenConverter{}
	components := openapi3.Components{}

	authToken := apidef.AuthConfig{
		UseParam:          true,
		ParamName:         "Auth-Param",
		UseCookie:         true,
		CookieName:        "Auth-Cookie",
		AuthHeaderName:    "Auth-Header",
		UseCertificate:    true,
		ValidateSignature: true,
		Signature: apidef.SignatureConfig{
			Algorithm:        "test-alg",
			Header:           "test-header",
			Secret:           "test-secret",
			AllowedClockSkew: 1,
			ErrorCode:        300,
			ErrorMessage:     "test-error-message",
		},
	}

	api := apidef.APIDefinition{
		AuthConfigs: map[string]apidef.AuthConfig{
			"authToken": authToken,
		},
	}

	api.AuthConfigs["authToken"]=apidef.AuthConfig{
		AuthHeaderName:"asd",
		ValidateSignature:true,
		UseCertificate:true,
		UseCookie:false,
		ParamName:"param-auth",
	}

	tokenConverter.ConvertToSwagger(api, &components)

	inBytes, _ := json.MarshalIndent(components, "", "   ")
	yamlInBytes, _ := yaml.JSONToYAML(inBytes)
	fmt.Println(string(yamlInBytes))

	/*var convertedAPI apidef.APIDefinition
	tokenConverter.ConvertToTykAPIDefinition(components, &convertedAPI)

	inBytes, _ := json.MarshalIndent(convertedAPI, "", "   ")
	fmt.Println(string(inBytes))*/

}

func TestJWTConverter_ConvertToSwagger(t *testing.T) {
	jwtConverter := JWTConverter{}
	components := openapi3.Components{}
	api := apidef.APIDefinition{
		JWTDefaultPolicies: []string{"default-pol1", "default-pol2"},
		JWTPolicyFieldName: "pol",
		JWTScopeClaimName:  "scope-claim",
		AuthConfigs: map[string]apidef.AuthConfig{
			"jwt": {
				UseParam:          true,
				ParamName:         "Auth-Param",
				UseCookie:         true,
				CookieName:        "Auth-Cookie",
				AuthHeaderName:    "Auth-Header",
				UseCertificate:    true,
				ValidateSignature: true,
				Signature: apidef.SignatureConfig{
					Algorithm:        "test-alg",
					Header:           "test-header",
					Secret:           "test-secret",
					AllowedClockSkew: 1,
					ErrorCode:        300,
					ErrorMessage:     "test-error-message",
				},
			},
		},
	}

	jwtConverter.AppendToSwagger(api, &components)

	inBytes, _ := json.MarshalIndent(components, "", "   ")
	yamlInBytes, _ := yaml.JSONToYAML(inBytes)
	fmt.Println(string(yamlInBytes))

}

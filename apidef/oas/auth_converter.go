package oas

import (
	"encoding/json"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

type XTykJWTConfig struct {
	SkipKid                 bool              `json:"skip-kid,omitempty"`
	Source                  string            `json:"source,omitempty"`
	SigningMethod           string            `json:"signing-method,omitempty"`
	NotBeforeValidationSkew uint64            `json:"not-before-validation-skew,omitempty"`
	IssuedAtValidationSkew  uint64            `json:"issued-at-validation-skew,omitempty"`
	ExpiresAtValidationSkew uint64            `json:"expires-at-validation-skew,omitempty"`
	IdentityBaseField       string            `json:"identity-base-field,omitempty"`
	ClientBaseField         string            `json:"client-base-field,omitempty"`
	ScopeToPolicyMapping    map[string]string `json:"scope-to-policy-mapping,omitempty"`
	PolicyFieldName         string            `json:"policy-field-name,omitempty"`
	ScopeClaimName          string            `json:"scope-claim-name,omitempty"`
	DefaultPolicies         []string          `json:"default-policies,omitempty"`
}

type XTykAuthTokenConfig struct {
	EnableClientCertificate bool       `bson:"enable-client-certificate,omitempty" json:"enable-client-certificate,omitempty"`
	ValidateSignature       bool       `bson:"validate-signature,omitempty" json:"validate-signature,omitempty"`
	Signature               *Signature `bson:"signature,omitempty" json:"signature,omitempty"`
}

type Signature struct {
	Algorithm        string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	Header           string `bson:"header,omitempty" json:"header,omitempty"`
	Secret           string `bson:"secret,omitempty" json:"secret,omitempty"`
	AllowedClockSkew int64  `bson:"allowed-clock-skew,omitempty" json:"allowed-clock-skew,omitempty"`
	ErrorCode        int    `bson:"error-code,omitempty" json:"error-code,omitempty"`
	ErrorMessage     string `bson:"error-message,omitempty" json:"error-message,omitempty"`
}

type XTykAuthSources struct {
	Cookie *AuthSource `bson:"cookie,omitempty" json:"cookie,omitempty"`
	Param  *AuthSource `bson:"param,omitempty" json:"param,omitempty"`
}

type AuthSource struct {
	Enable bool   `bson:"enable,omitempty" json:"enable,omitempty"`
	Name   string `bson:"name,omitempty" json:"name,omitempty"`
}

type AuthTokenConverter struct{}

func (c AuthTokenConverter) ConvertToSwagger(api apidef.APIDefinition, components *openapi3.Components) {
	if api.AuthConfigs == nil {
		return
	}

	authToken, ok := api.AuthConfigs["authToken"]
	if !ok || (apidef.AuthConfig{} == authToken) {
		return
	}

	if components == nil {
		components = &openapi3.Components{}
	}

	if components.SecuritySchemes == nil {
		components.SecuritySchemes = make(map[string]*openapi3.SecuritySchemeRef)
	}

	securitySchemeRef := &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: "apiKey",
			In:   "header",
			Name: authToken.AuthHeaderName,
		},
	}

	securitySchemeRef.Value.Extensions = make(map[string]interface{})

	// * Set XTykAuthSources
	xTykAuthSources := &XTykAuthSources{
		Cookie: c.fillAuthSource(authToken.UseCookie, authToken.CookieName),
		Param:  c.fillAuthSource(authToken.UseParam, authToken.ParamName),
	}

	if (*xTykAuthSources != XTykAuthSources{}) {
		securitySchemeRef.Value.Extensions["x-tyk-auth-sources"] = xTykAuthSources
	}

	// * Set XTykAuthTokenConfig
	xTykAuthTokenConfig := &XTykAuthTokenConfig{
		EnableClientCertificate: authToken.UseCertificate,
		ValidateSignature:       authToken.ValidateSignature,
	}

	// ** Set XTykAuthTokenConfig.Signature
	if (authToken.Signature != apidef.SignatureConfig{}) {
		xTykAuthTokenConfig.Signature = &Signature{
			Algorithm:        authToken.Signature.Algorithm,
			Header:           authToken.Signature.Header,
			Secret:           authToken.Signature.Secret,
			AllowedClockSkew: authToken.Signature.AllowedClockSkew,
			ErrorCode:        authToken.Signature.ErrorCode,
			ErrorMessage:     authToken.Signature.ErrorMessage,
		}
	}

	if (*xTykAuthTokenConfig != XTykAuthTokenConfig{}) {
		securitySchemeRef.Value.Extensions["x-tyk-auth-config"] = xTykAuthTokenConfig
	}

	components.SecuritySchemes["token"] = securitySchemeRef
}

func (c AuthTokenConverter) fillAuthSource(enable bool, name string) (authSource *AuthSource) {
	if enable || name != "" {
		authSource = &AuthSource{
			Enable: enable,
			Name:   name,
		}
	}

	return
}

func (c AuthTokenConverter) ConvertToTykAPIDefinition(components openapi3.Components, api *apidef.APIDefinition) {
	if components.SecuritySchemes == nil {
		return
	}

	securitySchemeRef, ok := components.SecuritySchemes["token"]
	if !ok {
		return
	}

	securityScheme := securitySchemeRef.Value
	if securityScheme == nil {
		return
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	authToken := apidef.AuthConfig{
		AuthHeaderName: securityScheme.Name,
	}

	if intXTykAuthSources, ok := securityScheme.Extensions["x-tyk-auth-sources"]; ok {
		var xTykAuthSources *XTykAuthSources
		if xTykAuthSources, ok = intXTykAuthSources.(*XTykAuthSources); !ok {
			rawOperation := intXTykAuthSources.(json.RawMessage)
			_ = json.Unmarshal(rawOperation, &xTykAuthSources)
		}

		if param := xTykAuthSources.Param; param != nil {
			authToken.UseParam = xTykAuthSources.Param.Enable
			authToken.ParamName = xTykAuthSources.Param.Name
		}

		if cookie := xTykAuthSources.Cookie; cookie != nil {
			authToken.UseCookie = cookie.Enable
			authToken.CookieName = cookie.Name
		}
	}

	if intXTykAuthTokenConfig, ok := securityScheme.Extensions["x-tyk-auth-config"]; ok {
		var xTykAuthTokenConfig *XTykAuthTokenConfig
		if xTykAuthTokenConfig, ok = intXTykAuthTokenConfig.(*XTykAuthTokenConfig); !ok {
			rawOperation := intXTykAuthTokenConfig.(json.RawMessage)
			_ = json.Unmarshal(rawOperation, &xTykAuthTokenConfig)
		}

		authToken.UseCertificate = xTykAuthTokenConfig.EnableClientCertificate
		authToken.ValidateSignature = xTykAuthTokenConfig.ValidateSignature
		if signature := xTykAuthTokenConfig.Signature; signature != nil {
			authToken.Signature = apidef.SignatureConfig{
				Algorithm:        signature.Algorithm,
				Header:           signature.Header,
				Secret:           signature.Secret,
				AllowedClockSkew: signature.AllowedClockSkew,
				ErrorCode:        signature.ErrorCode,
				ErrorMessage:     signature.ErrorMessage,
			}
		}
	}

	api.AuthConfigs["authToken"] = authToken
}

type JWTConverter struct{}

func (c JWTConverter) AppendToSwagger(api apidef.APIDefinition, components *openapi3.Components) {
	jwt := api.AuthConfigs["jwt"]

	if components == nil {
		components = &openapi3.Components{}
	}

	if components.SecuritySchemes == nil {
		components.SecuritySchemes = make(map[string]*openapi3.SecuritySchemeRef)
	}

	components.SecuritySchemes["jwt"] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: "apiKey",
			In:   "header",
			Name: jwt.AuthHeaderName,
			ExtensionProps: openapi3.ExtensionProps{
				Extensions: map[string]interface{}{
					"x-tyk-auth-sources": &XTykAuthSources{
						Cookie: &AuthSource{
							Enable: jwt.UseCookie,
							Name:   jwt.CookieName,
						},
						Param: &AuthSource{
							Enable: jwt.UseParam,
							Name:   jwt.ParamName,
						},
					},
					"x-tyk-auth-config": &XTykJWTConfig{
						api.JWTSkipKid,
						api.JWTSource,
						api.JWTSigningMethod,
						api.JWTNotBeforeValidationSkew,
						api.JWTIssuedAtValidationSkew,
						api.JWTExpiresAtValidationSkew,
						api.JWTIdentityBaseField,
						api.JWTClientIDBaseField,
						api.JWTScopeToPolicyMapping,
						api.JWTPolicyFieldName,
						api.JWTScopeClaimName,
						api.JWTDefaultPolicies,
					},
				},
			},
		},
	}
}

package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	apiKey = "apiKey"

	header = "header"
	query  = "query"
	cookie = "cookie"
)

func (s *OAS) fillToken(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillApiKeyScheme(&authConfig)

	token := &Token{}
	token.Enabled = api.UseStandardAuth
	token.AuthSources.Fill(authConfig)
	token.EnableClientCertificate = authConfig.UseCertificate
	if token.Signature == nil {
		token.Signature = &Signature{}
	}

	token.Signature.Fill(authConfig)
	if ShouldOmit(token.Signature) {
		token.Signature = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = token

	if ShouldOmit(token) {
		delete(s.getTykSecuritySchemes(), authConfig.Name)
	}
}

func (s *OAS) extractTokenTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{DisableHeader: true}

	if token := s.getTykTokenAuth(name); token != nil {
		api.UseStandardAuth = token.Enabled
		authConfig.UseCertificate = token.EnableClientCertificate
		token.AuthSources.ExtractTo(&authConfig)
		if token.Signature != nil {
			token.Signature.ExtractTo(&authConfig)
		}
	}

	s.extractApiKeySchemeTo(&authConfig, name)

	api.AuthConfigs[apidef.AuthTokenType] = authConfig
}

func (s *OAS) extractSecurityTo(api *apidef.APIDefinition) {
	if a := s.getTykAuthentication(); a != nil {
		api.UseKeylessAccess = !a.Enabled
		api.StripAuthData = a.StripAuthorizationData
		api.BaseIdentityProvidedBy = a.BaseIdentityProvider
	} else {
		api.UseKeylessAccess = true
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	if len(s.Security) == 0 {
		return
	}

	for name := range s.Security[0] {
		switch s.Components.SecuritySchemes[name].Value.Type {
		case apiKey:
			s.extractTokenTo(api, name)
		}
	}
}

func (s *OAS) fillSecurity(api apidef.APIDefinition) {
	a := s.GetTykExtension().Server.Authentication
	if a == nil {
		a = &Authentication{}
		s.GetTykExtension().Server.Authentication = a
	}

	if a.SecuritySchemes == nil {
		s.GetTykExtension().Server.Authentication.SecuritySchemes = make(map[string]interface{})
	}

	a.Enabled = !api.UseKeylessAccess
	a.StripAuthorizationData = api.StripAuthData
	a.BaseIdentityProvider = api.BaseIdentityProvidedBy

	s.fillToken(api)

	if ShouldOmit(a) {
		s.GetTykExtension().Server.Authentication = nil
	}
}

func (s *OAS) fillApiKeyScheme(ac *apidef.AuthConfig) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[ac.Name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[ac.Name] = ref
	}

	var loc, key string

	switch {
	case ref.Value.In == header || (ref.Value.In == "" && ac.AuthHeaderName != ""):
		loc = header
		key = ac.AuthHeaderName
		ac.AuthHeaderName = ""
	case ref.Value.In == query || (ref.Value.In == "" && ac.ParamName != ""):
		loc = query
		key = ac.ParamName
		ac.ParamName = ""
	case ref.Value.In == cookie || (ref.Value.In == "" && ac.CookieName != ""):
		loc = cookie
		key = ac.CookieName
		ac.CookieName = ""
	}

	ref.Value.WithName(key).WithIn(loc).WithType(apiKey)

	s.appendSecurity(ac.Name)
}

func (s *OAS) extractApiKeySchemeTo(ac *apidef.AuthConfig, name string) {
	ref := s.Components.SecuritySchemes[name]
	ac.Name = name

	switch ref.Value.In {
	case header:
		ac.AuthHeaderName = ref.Value.Name
	case query:
		ac.ParamName = ref.Value.Name
	case cookie:
		ac.CookieName = ref.Value.Name
	}
}

func (s *OAS) appendSecurity(name string) {
	if len(s.Security) == 0 {
		s.Security.With(openapi3.NewSecurityRequirement())
	}

	if _, found := s.Security[0][name]; !found {
		s.Security[0][name] = []string{}
	}
}

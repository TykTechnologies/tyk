package apidef

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationResult_HasErrors(t *testing.T) {
	result := ValidationResult{}
	assert.False(t, result.HasErrors())
	result.AppendError(errors.New("error"))
	assert.True(t, result.HasErrors())
}

func TestValidationResult_FirstError(t *testing.T) {
	firstErr := errors.New("first")
	secondErr := errors.New("second")

	result := ValidationResult{}
	result.AppendError(firstErr)
	result.AppendError(secondErr)

	assert.Equal(t, firstErr, result.FirstError())
}

func TestValidationResult_ErrorStrings(t *testing.T) {
	result := ValidationResult{
		Errors: []error{
			ErrDuplicateDataSourceName,
		},
	}

	expectedErrorStrings := []string{
		ErrDuplicateDataSourceName.Error(),
	}

	assert.Equal(t, expectedErrorStrings, result.ErrorStrings())
}

func runValidationTest(apiDef *APIDefinition, ruleSet ValidationRuleSet, expectedValidationResult ValidationResult) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		result := Validate(apiDef, ruleSet)
		assert.Equal(t, expectedValidationResult.IsValid, result.IsValid)
		assert.ElementsMatch(t, expectedValidationResult.Errors, result.Errors)
	}
}

func TestRuleUniqueDataSourceNames_Validate(t *testing.T) {
	ruleSet := ValidationRuleSet{
		&RuleUniqueDataSourceNames{},
	}

	t.Run("should return invalid when data source name is duplicated", runValidationTest(
		&APIDefinition{
			GraphQL: GraphQLConfig{
				Enabled: true,
				Version: GraphQLConfigVersion2,
				Engine: GraphQLEngineConfig{
					DataSources: []GraphQLEngineDataSource{
						{
							Name: "     DataSource",
						},
						{
							Name: "datasource     ",
						},
					},
				},
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				ErrDuplicateDataSourceName,
			},
		},
	))

	t.Run("return valid when data source names are not duplicated", runValidationTest(
		&APIDefinition{
			GraphQL: GraphQLConfig{
				Enabled: true,
				Version: GraphQLConfigVersion2,
				Engine: GraphQLEngineConfig{
					DataSources: []GraphQLEngineDataSource{
						{
							Name: "datasource 1",
						},
						{
							Name: "datasource 2",
						},
					},
				},
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: true,
			Errors:  nil,
		},
	))

	t.Run("return valid when there are no data sources", runValidationTest(
		&APIDefinition{
			GraphQL: GraphQLConfig{
				Enabled: true,
				Version: GraphQLConfigVersion2,
				Engine: GraphQLEngineConfig{
					DataSources: []GraphQLEngineDataSource{},
				},
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: true,
			Errors:  nil,
		},
	))

}

func TestRuleAtLeastEnableOneAuthConfig_Validate(t *testing.T) {
	ruleSet := ValidationRuleSet{
		&RuleAtLeastEnableOneAuthSource{},
	}
	t.Run("should return invalid when all sources are disabled for enabled auth mechanisms", runValidationTest(
		&APIDefinition{
			UseStandardAuth: true,
			UseOauth2:       true,
			AuthConfigs: map[string]AuthConfig{
				"authToken": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"oauth": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"jwt": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"oidc": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"hmac": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"coprocess": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				fmt.Errorf(ErrAllAuthSourcesDisabled, "authToken"),
				fmt.Errorf(ErrAllAuthSourcesDisabled, "oauth"),
			},
		},
	))

	t.Run("should return valid when at least one source is enabled for enabled auth mechanisms", runValidationTest(
		&APIDefinition{
			UseStandardAuth: true,
			UseOauth2:       true,
			AuthConfigs: map[string]AuthConfig{
				"authToken": {
					UseParam:      true,
					DisableHeader: true,
					UseCookie:     false,
				},
				"oauth": {
					UseParam:      false,
					DisableHeader: false,
					UseCookie:     false,
				},
				"jwt": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"oidc": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"hmac": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
				"coprocess": {
					UseParam:      false,
					DisableHeader: true,
					UseCookie:     false,
				},
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: true,
			Errors:  nil,
		},
	))
}

func TestRuleValidateIPList_Validate(t *testing.T) {
	ruleSet := ValidationRuleSet{
		&RuleValidateIPList{},
	}

	t.Run("valid IP and CIDR", runValidationTest(
		&APIDefinition{
			EnableIpWhiteListing: true,
			AllowedIPs: []string{
				"192.168.0.10",
				"192.168.2.1/24",
			},
			EnableIpBlacklisting: true,
			BlacklistedIPs: []string{
				"192.168.0.20",
				"192.168.3.1/24",
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: true,
			Errors:  nil,
		},
	))

	t.Run("invalid CIDR", runValidationTest(
		&APIDefinition{
			EnableIpWhiteListing: true,
			AllowedIPs: []string{
				"192.168.2.1/bob",
			},
			EnableIpBlacklisting: true,
			BlacklistedIPs: []string{
				"192.168.3.1/blah",
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				fmt.Errorf(ErrInvalidIPCIDR, "192.168.2.1/bob"),
				fmt.Errorf(ErrInvalidIPCIDR, "192.168.3.1/blah"),
			},
		},
	))

	t.Run("invalid IP and CIDR", runValidationTest(
		&APIDefinition{
			EnableIpWhiteListing: true,
			AllowedIPs: []string{
				"bob",
				"192.168.2.1/24",
			},
			EnableIpBlacklisting: true,
			BlacklistedIPs: []string{
				"blah",
				"192.168.3.1/24",
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				fmt.Errorf(ErrInvalidIPCIDR, "bob"),
				fmt.Errorf(ErrInvalidIPCIDR, "blah"),
			},
		},
	))

	t.Run("do not validate allowed IPs when whitelisting not enabled", runValidationTest(
		&APIDefinition{
			EnableIpWhiteListing: false,
			AllowedIPs: []string{
				"bob",
				"192.168.2.1/24",
			},
			EnableIpBlacklisting: true,
			BlacklistedIPs: []string{
				"blah",
				"192.168.3.1/24",
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				fmt.Errorf(ErrInvalidIPCIDR, "blah"),
			},
		},
	))

	t.Run("do not validate blacklist when not enabled", runValidationTest(
		&APIDefinition{
			EnableIpWhiteListing: true,
			AllowedIPs: []string{
				"bob",
				"192.168.2.1/24",
			},
			EnableIpBlacklisting: false,
			BlacklistedIPs: []string{
				"blah",
				"192.168.3.1/24",
			},
		},
		ruleSet,
		ValidationResult{
			IsValid: false,
			Errors: []error{
				fmt.Errorf(ErrInvalidIPCIDR, "bob"),
			},
		},
	))
}

func TestRuleValidateEnforceTimeout_Validate(t *testing.T) {
	ruleSet := ValidationRuleSet{
		&RuleValidateEnforceTimeout{},
	}

	getAPIDef := func(hardTimeouts []HardTimeoutMeta) *APIDefinition {
		return &APIDefinition{
			VersionData: VersionData{
				Versions: map[string]VersionInfo{
					"Default": {
						Name: "Default",
						ExtendedPaths: ExtendedPathsSet{
							HardTimeouts: hardTimeouts,
						},
					},
				},
			},
		}
	}

	testCases := []struct {
		name   string
		apiDef *APIDefinition
		result ValidationResult
	}{
		{
			name: "negative timeout",
			apiDef: getAPIDef([]HardTimeoutMeta{
				{
					Disabled: false,
					Path:     "/get",
					Method:   http.MethodGet,
					TimeOut:  -1,
				},
			}),
			result: ValidationResult{
				IsValid: false,
				Errors:  []error{ErrInvalidTimeoutValue},
			},
		},
		{
			name: "negative timeout for one among multiple paths",
			apiDef: getAPIDef([]HardTimeoutMeta{
				{
					Disabled: false,
					Path:     "/post",
					Method:   http.MethodGet,
					TimeOut:  -1,
				},
				{
					Disabled: false,
					Path:     "/get",
					Method:   http.MethodGet,
					TimeOut:  10,
				},
			}),
			result: ValidationResult{
				IsValid: false,
				Errors:  []error{ErrInvalidTimeoutValue},
			},
		},
		{
			name: "positive timeout",
			apiDef: getAPIDef([]HardTimeoutMeta{
				{
					Disabled: true,
					Path:     "/post",
					Method:   http.MethodGet,
					TimeOut:  10,
				},
			}),
			result: ValidationResult{
				IsValid: true,
				Errors:  nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, runValidationTest(tc.apiDef, ruleSet, tc.result))
	}
}

func TestRuleUpstreamAuth_Validate(t *testing.T) {
	ruleSet := ValidationRuleSet{
		&RuleUpstreamAuth{},
	}

	testCases := []struct {
		name         string
		upstreamAuth UpstreamAuth
		result       ValidationResult
	}{
		{
			name: "not enabled",
			upstreamAuth: UpstreamAuth{
				Enabled: false,
			},
			result: ValidationResult{
				IsValid: true,
				Errors:  nil,
			},
		},
		{
			name: "basic auth and OAuth enabled",
			upstreamAuth: UpstreamAuth{
				Enabled: true,
				BasicAuth: UpstreamBasicAuth{
					Enabled: true,
				},
				OAuth: UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{OAuthAuthorizationTypeClientCredentials},
				},
			},
			result: ValidationResult{
				IsValid: false,
				Errors: []error{
					ErrMultipleUpstreamAuthEnabled,
				},
			},
		},
		{
			name: "no upstream OAuth authorization type specified",
			upstreamAuth: UpstreamAuth{
				Enabled: true,
				OAuth: UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{},
				},
			},
			result: ValidationResult{
				IsValid: false,
				Errors:  []error{ErrUpstreamOAuthAuthorizationTypeRequired},
			},
		},
		{
			name: "multiple upstream OAuth authorization type specified",
			upstreamAuth: UpstreamAuth{
				Enabled: true,
				OAuth: UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{OAuthAuthorizationTypeClientCredentials, OAuthAuthorizationTypePassword},
				},
			},
			result: ValidationResult{
				IsValid: false,
				Errors:  []error{ErrMultipleUpstreamOAuthAuthorizationType},
			},
		},
		{
			name: "invalid upstream OAuth authorization type specified",
			upstreamAuth: UpstreamAuth{
				Enabled: true,
				OAuth: UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{"auth-type1"},
				},
			},
			result: ValidationResult{
				IsValid: false,
				Errors:  []error{ErrInvalidUpstreamOAuthAuthorizationType},
			},
		},
	}

	for _, tc := range testCases {
		apiDef := &APIDefinition{
			UpstreamAuth: tc.upstreamAuth,
		}

		t.Run(tc.name, runValidationTest(apiDef, ruleSet, tc.result))
	}
}

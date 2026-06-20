package apidef

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-097
// SW-REQ-097:nominal:nominal
// SW-REQ-097:boundary:nominal
// SW-REQ-097:error_handling:nominal
// SW-REQ-097:error_handling:negative
// SW-REQ-097:determinism:nominal
func TestAPIDefinitionValidatorPreservesSupportBehavior(t *testing.T) {
	t.Run("validation results and rule dispatch preserve error state", func(t *testing.T) {
		result := ValidationResult{}
		assert.False(t, result.HasErrors())
		assert.Zero(t, result.ErrorCount())
		assert.NoError(t, result.FirstError())

		firstErr := errors.New("first")
		secondErr := errors.New("second")
		result.AppendError(firstErr)
		result.AppendError(secondErr)

		assert.True(t, result.HasErrors())
		assert.Equal(t, 2, result.ErrorCount())
		assert.Equal(t, firstErr, result.FirstError())
		assert.Equal(t, secondErr, result.ErrorAt(1))
		assert.Equal(t, []string{"first", "second"}, result.ErrorStrings())

		dispatched := Validate(&APIDefinition{}, ValidationRuleSet{
			validationRuleFunc(func(_ *APIDefinition, validationResult *ValidationResult) {
				validationResult.IsValid = false
				validationResult.AppendError(firstErr)
			}),
			validationRuleFunc(func(_ *APIDefinition, validationResult *ValidationResult) {
				validationResult.AppendError(secondErr)
			}),
		})

		assert.False(t, dispatched.IsValid)
		assert.Equal(t, []error{firstErr, secondErr}, dispatched.Errors)
	})

	t.Run("default rules accept an empty support model", func(t *testing.T) {
		result := Validate(&APIDefinition{}, DefaultValidationRuleSet)
		assert.True(t, result.IsValid)
		assert.Empty(t, result.Errors)
	})

	t.Run("validation rules report deterministic local support errors", func(t *testing.T) {
		tests := []struct {
			name       string
			apiDef     *APIDefinition
			ruleSet    ValidationRuleSet
			wantErrors []error
		}{
			{
				name: "duplicate graphql data source names are normalized",
				apiDef: &APIDefinition{
					GraphQL: GraphQLConfig{
						Engine: GraphQLEngineConfig{
							DataSources: []GraphQLEngineDataSource{
								{Name: "  DataSource  "},
								{Name: "datasource"},
							},
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleUniqueDataSourceNames{}},
				wantErrors: []error{ErrDuplicateDataSourceName},
			},
			{
				name: "enabled auth mechanisms need at least one active source",
				apiDef: &APIDefinition{
					UseStandardAuth: true,
					UseOauth2:       true,
					AuthConfigs: map[string]AuthConfig{
						"oauth": {
							UseParam:      false,
							UseCookie:     false,
							DisableHeader: true,
						},
						"authToken": {
							UseParam:      false,
							UseCookie:     false,
							DisableHeader: true,
						},
						"jwt": {
							UseParam:      false,
							UseCookie:     false,
							DisableHeader: true,
						},
					},
				},
				ruleSet: ValidationRuleSet{&RuleAtLeastEnableOneAuthSource{}},
				wantErrors: []error{
					fmt.Errorf(ErrAllAuthSourcesDisabled, "authToken"),
					fmt.Errorf(ErrAllAuthSourcesDisabled, "oauth"),
				},
			},
			{
				name: "enabled IP lists reject malformed IP and CIDR entries",
				apiDef: &APIDefinition{
					EnableIpWhiteListing: true,
					AllowedIPs:           []string{"not-an-ip"},
					EnableIpBlacklisting: true,
					BlacklistedIPs:       []string{"192.168.1.1/bad"},
				},
				ruleSet: ValidationRuleSet{&RuleValidateIPList{}},
				wantErrors: []error{
					fmt.Errorf(ErrInvalidIPCIDR, "not-an-ip"),
					fmt.Errorf(ErrInvalidIPCIDR, "192.168.1.1/bad"),
				},
			},
			{
				name: "hard timeout cannot be negative",
				apiDef: &APIDefinition{
					VersionData: VersionData{
						Versions: map[string]VersionInfo{
							"Default": {
								ExtendedPaths: ExtendedPathsSet{
									HardTimeouts: []HardTimeoutMeta{
										{
											Path:    "/slow",
											Method:  http.MethodGet,
											TimeOut: -1,
										},
									},
								},
							},
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleValidateEnforceTimeout{}},
				wantErrors: []error{ErrInvalidTimeoutValue},
			},
			{
				name: "basic and oauth upstream auth modes are mutually exclusive",
				apiDef: &APIDefinition{
					UpstreamAuth: UpstreamAuth{
						Enabled: true,
						BasicAuth: UpstreamBasicAuth{
							Enabled: true,
						},
						OAuth: UpstreamOAuth{
							Enabled:               true,
							AllowedAuthorizeTypes: []string{OAuthAuthorizationTypeClientCredentials},
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleUpstreamAuth{}},
				wantErrors: []error{ErrMultipleUpstreamAuthEnabled},
			},
			{
				name: "upstream oauth requires an authorization type",
				apiDef: &APIDefinition{
					UpstreamAuth: UpstreamAuth{
						Enabled: true,
						OAuth: UpstreamOAuth{
							Enabled: true,
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleUpstreamAuth{}},
				wantErrors: []error{ErrUpstreamOAuthAuthorizationTypeRequired},
			},
			{
				name: "upstream oauth rejects multiple authorization types",
				apiDef: &APIDefinition{
					UpstreamAuth: UpstreamAuth{
						Enabled: true,
						OAuth: UpstreamOAuth{
							Enabled: true,
							AllowedAuthorizeTypes: []string{
								OAuthAuthorizationTypeClientCredentials,
								OAuthAuthorizationTypePassword,
							},
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleUpstreamAuth{}},
				wantErrors: []error{ErrMultipleUpstreamOAuthAuthorizationType},
			},
			{
				name: "upstream oauth rejects unknown authorization type",
				apiDef: &APIDefinition{
					UpstreamAuth: UpstreamAuth{
						Enabled: true,
						OAuth: UpstreamOAuth{
							Enabled:               true,
							AllowedAuthorizeTypes: []string{"unknown"},
						},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleUpstreamAuth{}},
				wantErrors: []error{ErrInvalidUpstreamOAuthAuthorizationType},
			},
			{
				name: "load balancing needs at least one expanded target",
				apiDef: &APIDefinition{
					Proxy: ProxyConfig{
						EnableLoadBalancing: true,
						Targets:             []string{},
					},
				},
				ruleSet:    ValidationRuleSet{&RuleLoadBalancingTargets{}},
				wantErrors: []error{ErrAllLoadBalancingTargetsZeroWeight},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := Validate(tt.apiDef, tt.ruleSet)
				require.False(t, result.IsValid)
				assert.ElementsMatch(t, tt.wantErrors, result.Errors)
			})
		}
	})

	t.Run("validation rules preserve enabled and disabled boundaries", func(t *testing.T) {
		tests := []struct {
			name    string
			apiDef  *APIDefinition
			ruleSet ValidationRuleSet
		}{
			{
				name: "unique data source names",
				apiDef: &APIDefinition{
					GraphQL: GraphQLConfig{
						Engine: GraphQLEngineConfig{
							DataSources: []GraphQLEngineDataSource{
								{Name: "one"},
								{Name: "two"},
							},
						},
					},
				},
				ruleSet: ValidationRuleSet{&RuleUniqueDataSourceNames{}},
			},
			{
				name: "auth source enabled by query parameter",
				apiDef: &APIDefinition{
					UseStandardAuth: true,
					AuthConfigs: map[string]AuthConfig{
						"authToken": {
							UseParam:      true,
							DisableHeader: true,
						},
					},
				},
				ruleSet: ValidationRuleSet{&RuleAtLeastEnableOneAuthSource{}},
			},
			{
				name: "valid IP and CIDR entries",
				apiDef: &APIDefinition{
					EnableIpWhiteListing: true,
					AllowedIPs:           []string{"127.0.0.1", "10.0.0.0/24"},
				},
				ruleSet: ValidationRuleSet{&RuleValidateIPList{}},
			},
			{
				name: "disabled IP lists are not inspected",
				apiDef: &APIDefinition{
					AllowedIPs:     []string{"not-an-ip"},
					BlacklistedIPs: []string{"not-an-ip"},
				},
				ruleSet: ValidationRuleSet{&RuleValidateIPList{}},
			},
			{
				name: "nonnegative hard timeout",
				apiDef: &APIDefinition{
					VersionData: VersionData{
						Versions: map[string]VersionInfo{
							"Default": {
								ExtendedPaths: ExtendedPathsSet{
									HardTimeouts: []HardTimeoutMeta{{TimeOut: 0}},
								},
							},
						},
					},
				},
				ruleSet: ValidationRuleSet{&RuleValidateEnforceTimeout{}},
			},
			{
				name: "disabled upstream auth is not inspected",
				apiDef: &APIDefinition{
					UpstreamAuth: UpstreamAuth{
						Enabled: false,
						OAuth: UpstreamOAuth{
							Enabled: true,
						},
					},
				},
				ruleSet: ValidationRuleSet{&RuleUpstreamAuth{}},
			},
			{
				name: "load balancing disabled permits empty targets",
				apiDef: &APIDefinition{
					Proxy: ProxyConfig{
						EnableLoadBalancing: false,
						Targets:             []string{},
					},
				},
				ruleSet: ValidationRuleSet{&RuleLoadBalancingTargets{}},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := Validate(tt.apiDef, tt.ruleSet)
				assert.True(t, result.IsValid)
				assert.Empty(t, result.Errors)
			})
		}
	})
}

type validationRuleFunc func(apiDef *APIDefinition, validationResult *ValidationResult)

func (f validationRuleFunc) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	f(apiDef, validationResult)
}

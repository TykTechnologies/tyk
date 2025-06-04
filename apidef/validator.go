package apidef

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

type ValidationResult struct {
	IsValid bool
	Errors  []error
}

func (v *ValidationResult) AppendError(err error) {
	v.Errors = append(v.Errors, err)
}

func (v *ValidationResult) HasErrors() bool {
	return v.ErrorCount() > 0
}

func (v *ValidationResult) FirstError() error {
	if v.ErrorCount() == 0 {
		return nil
	}

	return v.ErrorAt(0)
}

func (v *ValidationResult) ErrorAt(i int) error {
	if v.ErrorCount() < i {
		return nil
	}

	return v.Errors[i]
}

func (v *ValidationResult) ErrorCount() int {
	return len(v.Errors)
}

func (v *ValidationResult) ErrorStrings() []string {
	var errorStrings []string
	for _, err := range v.Errors {
		errorStrings = append(errorStrings, err.Error())
	}

	return errorStrings
}

type ValidationRuleSet []ValidationRule

var DefaultValidationRuleSet = ValidationRuleSet{
	&RuleUniqueDataSourceNames{},
	&RuleAtLeastEnableOneAuthSource{},
	&RuleValidateIPList{},
	&RuleValidateEnforceTimeout{},
	&RuleUpstreamAuth{},
}

func Validate(definition *APIDefinition, ruleSet ValidationRuleSet) ValidationResult {
	result := ValidationResult{
		IsValid: true,
		Errors:  nil,
	}

	for _, rule := range ruleSet {
		rule.Validate(definition, &result)
	}

	return result
}

type ValidationRule interface {
	Validate(apiDef *APIDefinition, validationResult *ValidationResult)
}

var ErrDuplicateDataSourceName = errors.New("duplicate data source names are not allowed")

type RuleUniqueDataSourceNames struct{}

func (r *RuleUniqueDataSourceNames) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	if apiDef.GraphQL.Engine.DataSources == nil || len(apiDef.GraphQL.Engine.DataSources) <= 1 {
		return
	}

	usedNames := map[string]bool{}
	for _, ds := range apiDef.GraphQL.Engine.DataSources {
		trimmedName := strings.TrimSpace(strings.ToLower(ds.Name))
		if usedNames[trimmedName] {
			validationResult.IsValid = false
			validationResult.AppendError(ErrDuplicateDataSourceName)
			return
		}

		usedNames[trimmedName] = true
	}
}

var ErrAllAuthSourcesDisabled = "all auth sources are disabled for %s, at least one of header/cookie/query must be enabled"

type RuleAtLeastEnableOneAuthSource struct{}

func (r *RuleAtLeastEnableOneAuthSource) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	authConfigs := make([]string, len(apiDef.AuthConfigs))
	i := 0
	for name := range apiDef.AuthConfigs {
		authConfigs[i] = name
		i++
	}

	sort.Strings(authConfigs)

	for _, name := range authConfigs {
		if shouldValidateAuthSource(name, apiDef) &&
			!(apiDef.AuthConfigs[name].UseParam || apiDef.AuthConfigs[name].UseCookie || !apiDef.AuthConfigs[name].DisableHeader) {
			validationResult.IsValid = false
			validationResult.AppendError(fmt.Errorf(ErrAllAuthSourcesDisabled, name))
		}
	}

}

func shouldValidateAuthSource(authType string, apiDef *APIDefinition) bool {
	switch authType {
	case "authToken":
		return apiDef.UseStandardAuth
	case "jwt":
		return apiDef.EnableJWT
	case "hmac":
		return apiDef.EnableSignatureChecking
	case "oauth":
		return apiDef.UseOauth2
	case "oidc":
		return apiDef.UseOpenID
	case "coprocess":
		return apiDef.EnableCoProcessAuth
	}

	return false
}

var ErrInvalidIPCIDR = "invalid IP/CIDR %q"

type RuleValidateIPList struct{}

func (r *RuleValidateIPList) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	if apiDef.EnableIpWhiteListing {
		if errs := r.validateIPAddr(apiDef.AllowedIPs); len(errs) > 0 {
			validationResult.IsValid = false
			validationResult.Errors = append(validationResult.Errors, errs...)
		}
	}

	if apiDef.EnableIpBlacklisting {
		if errs := r.validateIPAddr(apiDef.BlacklistedIPs); len(errs) > 0 {
			validationResult.IsValid = false
			validationResult.Errors = append(validationResult.Errors, errs...)
		}
	}
}

func (r *RuleValidateIPList) validateIPAddr(ips []string) []error {
	var errs []error
	for _, ip := range ips {
		if strings.Count(ip, "/") == 1 {
			_, _, err := net.ParseCIDR(ip)
			if err != nil {
				errs = append(errs, fmt.Errorf(ErrInvalidIPCIDR, ip))
			}

			continue
		}

		allowedIP := net.ParseIP(ip)
		if allowedIP == nil {
			errs = append(errs, fmt.Errorf(ErrInvalidIPCIDR, ip))
		}
	}

	return errs
}

var ErrInvalidTimeoutValue = errors.New("invalid timeout value")

type RuleValidateEnforceTimeout struct{}

func (r *RuleValidateEnforceTimeout) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	if apiDef.VersionData.Versions != nil {
		for _, vInfo := range apiDef.VersionData.Versions {
			for _, hardTimeOutMeta := range vInfo.ExtendedPaths.HardTimeouts {
				if hardTimeOutMeta.TimeOut < 0 {
					validationResult.IsValid = false
					validationResult.AppendError(ErrInvalidTimeoutValue)
					return
				}
			}
		}
	}
}

var (
	// ErrMultipleUpstreamAuthEnabled is the error to be returned when multiple upstream authentication modes are configured.
	ErrMultipleUpstreamAuthEnabled = errors.New("multiple upstream authentication modes not allowed")
	// ErrMultipleUpstreamOAuthAuthorizationType is the error to return when multiple OAuth authorization types are configured.
	ErrMultipleUpstreamOAuthAuthorizationType = errors.New("multiple upstream OAuth authorization type not allowed")
	// ErrUpstreamOAuthAuthorizationTypeRequired is the error to return when OAuth authorization type is not specified.
	ErrUpstreamOAuthAuthorizationTypeRequired = errors.New("upstream OAuth authorization type is required")
	// ErrInvalidUpstreamOAuthAuthorizationType is the error to return when configured OAuth authorization type is invalid.
	ErrInvalidUpstreamOAuthAuthorizationType = errors.New("invalid OAuth authorization type")
)

// RuleUpstreamAuth implements validations for upstream authentication configurations.
type RuleUpstreamAuth struct{}

// Validate validates api definition upstream authentication configurations.
func (r *RuleUpstreamAuth) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	upstreamAuth := apiDef.UpstreamAuth

	if !upstreamAuth.IsEnabled() {
		return
	}

	if upstreamAuth.BasicAuth.Enabled && upstreamAuth.OAuth.Enabled {
		validationResult.IsValid = false
		validationResult.AppendError(ErrMultipleUpstreamAuthEnabled)
	}

	upstreamOAuth := upstreamAuth.OAuth
	// only OAuth checks moving forward
	if !upstreamOAuth.IsEnabled() {
		return
	}

	if len(upstreamOAuth.AllowedAuthorizeTypes) == 0 {
		validationResult.IsValid = false
		validationResult.AppendError(ErrUpstreamOAuthAuthorizationTypeRequired)
		return
	}

	if len(upstreamAuth.OAuth.AllowedAuthorizeTypes) > 1 {
		validationResult.IsValid = false
		validationResult.AppendError(ErrMultipleUpstreamOAuthAuthorizationType)
	}

	if authType := upstreamAuth.OAuth.AllowedAuthorizeTypes[0]; authType != OAuthAuthorizationTypeClientCredentials && authType != OAuthAuthorizationTypePassword {
		validationResult.IsValid = false
		validationResult.AppendError(ErrInvalidUpstreamOAuthAuthorizationType)
	}
}

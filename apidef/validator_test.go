package apidef

import (
	"errors"
	"fmt"
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

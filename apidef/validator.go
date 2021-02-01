package apidef

import (
	"errors"
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

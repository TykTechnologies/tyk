// Package astvalidation implements the validation rules specified in the GraphQL specification.
package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// DefaultOperationValidator returns a fully initialized OperationValidator with all default rules registered
func DefaultOperationValidator() *OperationValidator {

	validator := OperationValidator{
		walker: astvisitor.NewWalker(48),
	}

	validator.RegisterRule(DocumentContainsExecutableOperation())
	validator.RegisterRule(OperationNameUniqueness())
	validator.RegisterRule(LoneAnonymousOperation())
	validator.RegisterRule(SubscriptionSingleRootField())
	validator.RegisterRule(FieldSelections())
	validator.RegisterRule(FieldSelectionMerging())
	validator.RegisterRule(ValidArguments())
	validator.RegisterRule(Values())
	validator.RegisterRule(ArgumentUniqueness())
	validator.RegisterRule(RequiredArguments())
	validator.RegisterRule(Fragments())
	validator.RegisterRule(DirectivesAreDefined())
	validator.RegisterRule(DirectivesAreInValidLocations())
	validator.RegisterRule(VariableUniqueness())
	validator.RegisterRule(DirectivesAreUniquePerLocation())
	validator.RegisterRule(VariablesAreInputTypes())
	validator.RegisterRule(AllVariableUsesDefined())
	validator.RegisterRule(AllVariablesUsed())

	return &validator
}

func NewOperationValidator(rules []Rule) *OperationValidator {
	validator := OperationValidator{
		walker: astvisitor.NewWalker(48),
	}

	for _, rule := range rules {
		validator.RegisterRule(rule)
	}

	return &validator
}

// OperationValidator orchestrates the validation process of Operations
type OperationValidator struct {
	walker astvisitor.Walker
}

// RegisterRule registers a rule to the OperationValidator
func (o *OperationValidator) RegisterRule(rule Rule) {
	rule(&o.walker)
}

// Validate validates the operation against the definition using the registered ruleset.
func (o *OperationValidator) Validate(operation, definition *ast.Document, report *operationreport.Report) ValidationState {

	if report == nil {
		report = &operationreport.Report{}
	}

	o.walker.Walk(operation, definition, report)

	if report.HasErrors() {
		return Invalid
	}
	return Valid
}

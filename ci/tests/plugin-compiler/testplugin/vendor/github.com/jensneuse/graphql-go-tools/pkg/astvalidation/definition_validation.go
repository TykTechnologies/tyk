package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func DefaultDefinitionValidator() *DefinitionValidator {
	validator := &DefinitionValidator{
		walker: astvisitor.NewWalker(48),
	}

	validator.RegisterRule(UniqueOperationTypes())
	validator.RegisterRule(UniqueTypeNames())
	validator.RegisterRule(UniqueFieldDefinitionNames())
	validator.RegisterRule(UniqueEnumValueNames())
	validator.RegisterRule(KnownTypeNames())

	return validator
}

type DefinitionValidator struct {
	walker astvisitor.Walker
}

func (d *DefinitionValidator) RegisterRule(rule Rule) {
	rule(&d.walker)
}

func (d *DefinitionValidator) Validate(definition *ast.Document, report *operationreport.Report) ValidationState {
	if report == nil {
		report = &operationreport.Report{}
	}

	d.walker.Walk(definition, nil, report)

	if report.HasErrors() {
		return Invalid
	}
	return Valid
}

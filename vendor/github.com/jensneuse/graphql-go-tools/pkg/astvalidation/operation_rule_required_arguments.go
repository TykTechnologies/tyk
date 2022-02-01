package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// RequiredArguments validates if all required arguments are present
func RequiredArguments() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := requiredArgumentsVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterFieldVisitor(&visitor)
	}
}

type requiredArgumentsVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (r *requiredArgumentsVisitor) EnterDocument(operation, definition *ast.Document) {
	r.operation = operation
	r.definition = definition
}

func (r *requiredArgumentsVisitor) EnterField(ref int) {

	fieldName := r.operation.FieldNameBytes(ref)
	inputValueDefinitions := r.definition.NodeFieldDefinitionArgumentsDefinitions(r.EnclosingTypeDefinition, fieldName)

	for _, i := range inputValueDefinitions {
		if r.definition.InputValueDefinitionArgumentIsOptional(i) {
			continue
		}

		name := r.definition.InputValueDefinitionNameBytes(i)

		argument, exists := r.operation.FieldArgument(ref, name)
		if !exists {
			r.StopWithExternalErr(operationreport.ErrArgumentRequiredOnField(name, fieldName))
			return
		}

		if r.operation.ArgumentValue(argument).Kind == ast.ValueKindNull {
			r.StopWithExternalErr(operationreport.ErrArgumentOnFieldMustNotBeNull(name, fieldName))
			return
		}
	}
}

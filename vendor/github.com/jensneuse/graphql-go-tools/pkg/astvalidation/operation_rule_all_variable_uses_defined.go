package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// AllVariableUsesDefined validates if used variables are defined within the operation
func AllVariableUsesDefined() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := allVariableUsesDefinedVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterArgumentVisitor(&visitor)
	}
}

type allVariableUsesDefinedVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (a *allVariableUsesDefinedVisitor) EnterDocument(operation, definition *ast.Document) {
	a.operation = operation
	a.definition = definition
}

func (a *allVariableUsesDefinedVisitor) EnterArgument(ref int) {

	if a.operation.Arguments[ref].Value.Kind != ast.ValueKindVariable {
		return // skip because no variable
	}

	if a.Ancestors[0].Kind != ast.NodeKindOperationDefinition {
		// skip because variable is not used in operation which happens in case normalization did not merge the fragment definition
		// this happens when a fragment is defined but not used which will itself lead to another validation error
		// in which case we can safely skip here
		return
	}

	variableName := a.operation.VariableValueNameBytes(a.operation.Arguments[ref].Value.Ref)

	for _, i := range a.operation.OperationDefinitions[a.Ancestors[0].Ref].VariableDefinitions.Refs {
		if bytes.Equal(variableName, a.operation.VariableDefinitionNameBytes(i)) {
			return // return OK because variable is defined
		}
	}

	// at this point we're safe to say this variable was not defined on the root operation of this argument
	argumentName := a.operation.ArgumentNameBytes(ref)
	a.StopWithExternalErr(operationreport.ErrVariableNotDefinedOnArgument(variableName, argumentName))
}

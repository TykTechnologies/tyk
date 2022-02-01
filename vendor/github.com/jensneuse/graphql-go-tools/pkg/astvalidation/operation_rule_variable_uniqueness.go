package astvalidation

import (
	"bytes"
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// VariableUniqueness validates if variables are unique in a given document
func VariableUniqueness() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := variableUniquenessVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterVariableDefinitionVisitor(&visitor)
	}
}

type variableUniquenessVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (v *variableUniquenessVisitor) EnterDocument(operation, definition *ast.Document) {
	v.operation = operation
	v.definition = definition
}

func (v *variableUniquenessVisitor) EnterVariableDefinition(ref int) {

	name := v.operation.VariableDefinitionNameBytes(ref)

	if v.Ancestors[0].Kind != ast.NodeKindOperationDefinition {
		return
	}

	variableDefinitions := v.operation.OperationDefinitions[v.Ancestors[0].Ref].VariableDefinitions.Refs

	for _, i := range variableDefinitions {
		if i == ref {
			continue
		}
		if bytes.Equal(name, v.operation.VariableDefinitionNameBytes(i)) {
			if v.Ancestors[0].Kind != ast.NodeKindOperationDefinition {
				v.StopWithInternalErr(fmt.Errorf("variable definition must have Operation ObjectDefinition as root ancestor, got: %s", v.Ancestors[0].Kind))
				return
			}
			operationName := v.operation.Input.ByteSlice(v.operation.OperationDefinitions[v.Ancestors[0].Ref].Name)
			v.StopWithExternalErr(operationreport.ErrVariableMustBeUnique(name, operationName))
			return
		}
	}
}

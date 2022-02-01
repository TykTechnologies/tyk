package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// VariablesAreInputTypes validates if variables are correct input types
func VariablesAreInputTypes() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := variablesAreInputTypesVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterVariableDefinitionVisitor(&visitor)
	}
}

type variablesAreInputTypesVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (v *variablesAreInputTypesVisitor) EnterDocument(operation, definition *ast.Document) {
	v.operation = operation
	v.definition = definition
}

func (v *variablesAreInputTypesVisitor) EnterVariableDefinition(ref int) {

	typeName := v.operation.ResolveTypeNameBytes(v.operation.VariableDefinitions[ref].Type)
	typeDefinitionNode, _ := v.definition.Index.FirstNodeByNameBytes(typeName)
	switch typeDefinitionNode.Kind {
	case ast.NodeKindInputObjectTypeDefinition, ast.NodeKindScalarTypeDefinition, ast.NodeKindEnumTypeDefinition:
		return
	default:
		variableName := v.operation.VariableDefinitionNameBytes(ref)
		v.StopWithExternalErr(operationreport.ErrVariableOfTypeIsNoValidInputValue(variableName, typeName))
		return
	}
}

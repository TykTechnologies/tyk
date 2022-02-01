package astvalidation

import (
	"bytes"
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// FieldSelections validates if all FieldSelections are possible and valid
func FieldSelections() Rule {
	return func(walker *astvisitor.Walker) {
		fieldDefined := fieldDefined{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&fieldDefined)
		walker.RegisterEnterFieldVisitor(&fieldDefined)
	}
}

type fieldDefined struct {
	*astvisitor.Walker
	operation  *ast.Document
	definition *ast.Document
}

func (f *fieldDefined) EnterDocument(operation, definition *ast.Document) {
	f.operation = operation
	f.definition = definition
}

func (f *fieldDefined) ValidateUnionField(ref int, enclosingTypeDefinition ast.Node) {
	if bytes.Equal(f.operation.FieldNameBytes(ref), literal.TYPENAME) {
		return
	}
	fieldName := f.operation.FieldNameBytes(ref)
	unionName := f.definition.NodeNameBytes(enclosingTypeDefinition)
	f.StopWithExternalErr(operationreport.ErrFieldSelectionOnUnion(fieldName, unionName))
}

func (f *fieldDefined) ValidateInterfaceObjectTypeField(ref int, enclosingTypeDefinition ast.Node) {
	fieldName := f.operation.FieldNameBytes(ref)
	if bytes.Equal(fieldName, literal.TYPENAME) {
		return
	}
	typeName := f.definition.NodeNameBytes(enclosingTypeDefinition)
	hasSelections := f.operation.FieldHasSelections(ref)
	definitions := f.definition.NodeFieldDefinitions(enclosingTypeDefinition)
	for _, i := range definitions {
		definitionName := f.definition.FieldDefinitionNameBytes(i)
		if bytes.Equal(fieldName, definitionName) {
			// field is defined
			fieldDefinitionTypeKind := f.definition.FieldDefinitionTypeNode(i).Kind
			switch {
			case hasSelections && fieldDefinitionTypeKind == ast.NodeKindScalarTypeDefinition:
				f.StopWithExternalErr(operationreport.ErrFieldSelectionOnScalar(fieldName, definitionName))
			case !hasSelections && (fieldDefinitionTypeKind != ast.NodeKindScalarTypeDefinition && fieldDefinitionTypeKind != ast.NodeKindEnumTypeDefinition):
				f.StopWithExternalErr(operationreport.ErrMissingFieldSelectionOnNonScalar(fieldName, typeName))
			}
			return
		}
	}

	f.StopWithExternalErr(operationreport.ErrFieldUndefinedOnType(fieldName, typeName))
}

func (f *fieldDefined) ValidateScalarField(ref int, enclosingTypeDefinition ast.Node) {
	fieldName := f.operation.FieldNameBytes(ref)
	scalarTypeName := f.operation.NodeNameBytes(enclosingTypeDefinition)
	f.StopWithExternalErr(operationreport.ErrFieldSelectionOnScalar(fieldName, scalarTypeName))
}

func (f *fieldDefined) EnterField(ref int) {
	switch f.EnclosingTypeDefinition.Kind {
	case ast.NodeKindUnionTypeDefinition:
		f.ValidateUnionField(ref, f.EnclosingTypeDefinition)
	case ast.NodeKindInterfaceTypeDefinition, ast.NodeKindObjectTypeDefinition:
		f.ValidateInterfaceObjectTypeField(ref, f.EnclosingTypeDefinition)
	case ast.NodeKindScalarTypeDefinition:
		f.ValidateScalarField(ref, f.EnclosingTypeDefinition)
	default:
		fieldName := f.operation.FieldNameBytes(ref)
		typeName := f.operation.NodeNameBytes(f.EnclosingTypeDefinition)
		f.StopWithInternalErr(fmt.Errorf("astvalidation/fieldDefined/EnterField: field: %s selection on type: %s unhandled", fieldName, typeName))
	}
}

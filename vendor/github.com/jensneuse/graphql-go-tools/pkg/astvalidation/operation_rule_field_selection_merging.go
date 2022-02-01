package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// FieldSelectionMerging validates if field selections can be merged
func FieldSelectionMerging() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := fieldSelectionMergingVisitor{Walker: walker}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterFieldVisitor(&visitor)
		walker.RegisterEnterOperationVisitor(&visitor)
		walker.RegisterEnterFragmentDefinitionVisitor(&visitor)
	}
}

type fieldSelectionMergingVisitor struct {
	*astvisitor.Walker
	definition, operation *ast.Document
	scalarRequirements    scalarRequirements
	nonScalarRequirements nonScalarRequirements
	refs                  []int
	pathCache             [256][32]ast.PathItem
	pathCacheIndex        int
}
type nonScalarRequirement struct {
	path                    ast.Path
	objectName              ast.ByteSlice
	fieldTypeRef            int
	fieldTypeDefinitionNode ast.Node
}

type nonScalarRequirements []nonScalarRequirement

func (f *fieldSelectionMergingVisitor) NonScalarRequirementsByPathField(path ast.Path, objectName ast.ByteSlice) []int {
	f.refs = f.refs[:0]
	for i := range f.nonScalarRequirements {
		if f.nonScalarRequirements[i].path.Equals(path) && f.nonScalarRequirements[i].objectName.Equals(objectName) {
			f.refs = append(f.refs, i)
		}
	}
	return f.refs
}

type scalarRequirement struct {
	path                    ast.Path
	objectName              ast.ByteSlice
	fieldRef                int
	fieldType               int
	enclosingTypeDefinition ast.Node
	fieldTypeDefinitionNode ast.Node
}

type scalarRequirements []scalarRequirement

func (f *fieldSelectionMergingVisitor) ScalarRequirementsByPathField(path ast.Path, objectName ast.ByteSlice) []int {
	f.refs = f.refs[:0]
	for i := range f.scalarRequirements {
		if f.scalarRequirements[i].path.Equals(path) && f.scalarRequirements[i].objectName.Equals(objectName) {
			f.refs = append(f.refs, i)
		}
	}
	return f.refs
}

func (f *fieldSelectionMergingVisitor) resetRequirements() {
	f.scalarRequirements = f.scalarRequirements[:0]
	f.nonScalarRequirements = f.nonScalarRequirements[:0]
}

func (f *fieldSelectionMergingVisitor) EnterDocument(operation, definition *ast.Document) {
	f.operation = operation
	f.definition = definition
	f.pathCacheIndex = 0
}

func (f *fieldSelectionMergingVisitor) EnterFragmentDefinition(ref int) {
	f.resetRequirements()
}

func (f *fieldSelectionMergingVisitor) EnterOperationDefinition(ref int) {
	f.resetRequirements()
}

func (f *fieldSelectionMergingVisitor) EnterField(ref int) {
	fieldName := f.operation.FieldNameBytes(ref)
	if bytes.Equal(fieldName, literal.TYPENAME) {
		return
	}
	objectName := f.operation.FieldAliasOrNameBytes(ref)
	definition, ok := f.definition.NodeFieldDefinitionByName(f.EnclosingTypeDefinition, fieldName)
	if !ok {
		enclosingTypeName := f.definition.NodeNameBytes(f.EnclosingTypeDefinition)
		f.StopWithExternalErr(operationreport.ErrFieldUndefinedOnType(fieldName, enclosingTypeName))
		return
	}

	fieldType := f.definition.FieldDefinitionType(definition)
	fieldDefinitionTypeNode := f.definition.FieldDefinitionTypeNode(definition)
	if fieldDefinitionTypeNode.Kind != ast.NodeKindScalarTypeDefinition {

		matchedRequirements := f.NonScalarRequirementsByPathField(f.Path, objectName)
		fieldDefinitionTypeKindPresentInRequirements := false
		for _, i := range matchedRequirements {

			if !f.potentiallySameObject(fieldDefinitionTypeNode, f.nonScalarRequirements[i].fieldTypeDefinitionNode) {
				if !objectName.Equals(f.nonScalarRequirements[i].objectName) {
					f.StopWithExternalErr(operationreport.ErrResponseOfDifferingTypesMustBeOfSameShape(objectName, f.nonScalarRequirements[i].objectName))
					return
				}
			} else if !f.definition.TypesAreCompatibleDeep(f.nonScalarRequirements[i].fieldTypeRef, fieldType) {
				left, err := f.definition.PrintTypeBytes(f.nonScalarRequirements[i].fieldTypeRef, nil)
				if err != nil {
					f.StopWithInternalErr(err)
					return
				}
				right, err := f.definition.PrintTypeBytes(fieldType, nil)
				if err != nil {
					f.StopWithInternalErr(err)
					return
				}
				f.StopWithExternalErr(operationreport.ErrTypesForFieldMismatch(objectName, left, right))
				return
			}

			if fieldDefinitionTypeNode.Kind != f.nonScalarRequirements[i].fieldTypeDefinitionNode.Kind {
				fieldDefinitionTypeKindPresentInRequirements = true
			}
		}

		if len(matchedRequirements) != 0 && fieldDefinitionTypeKindPresentInRequirements {
			return
		}

		var path ast.Path
		if f.pathCacheIndex != len(f.pathCache)-1 {
			path = f.pathCache[f.pathCacheIndex][:len(f.Path)]
			f.pathCacheIndex++
			for i := 0; i < len(f.Path); i++ {
				path[i] = f.Path[i]
			}
		} else {
			path = make(ast.Path, len(f.Path))
			copy(path, f.Path)
		}

		f.nonScalarRequirements = append(f.nonScalarRequirements, nonScalarRequirement{
			path:                    path,
			objectName:              objectName,
			fieldTypeRef:            fieldType,
			fieldTypeDefinitionNode: fieldDefinitionTypeNode,
		})
		return
	}

	matchedRequirements := f.ScalarRequirementsByPathField(f.Path, objectName)
	fieldDefinitionTypeKindPresentInRequirements := false

	for _, i := range matchedRequirements {
		if f.potentiallySameObject(f.scalarRequirements[i].enclosingTypeDefinition, f.EnclosingTypeDefinition) {
			if !f.operation.FieldsAreEqualFlat(f.scalarRequirements[i].fieldRef, ref) {
				f.StopWithExternalErr(operationreport.ErrDifferingFieldsOnPotentiallySameType(objectName))
				return
			}
		}
		if !f.definition.TypesAreCompatibleDeep(f.scalarRequirements[i].fieldType, fieldType) {
			left, err := f.definition.PrintTypeBytes(f.scalarRequirements[i].fieldType, nil)
			if err != nil {
				f.StopWithInternalErr(err)
				return
			}
			right, err := f.definition.PrintTypeBytes(fieldType, nil)
			if err != nil {
				f.StopWithInternalErr(err)
				return
			}
			f.StopWithExternalErr(operationreport.ErrFieldsConflict(objectName, left, right))
			return
		}

		if fieldDefinitionTypeNode.Kind != f.scalarRequirements[i].fieldTypeDefinitionNode.Kind {
			fieldDefinitionTypeKindPresentInRequirements = true
		}
	}

	if len(matchedRequirements) != 0 && fieldDefinitionTypeKindPresentInRequirements {
		return
	}

	var path ast.Path
	if f.pathCacheIndex != len(f.pathCache)-1 {
		path = f.pathCache[f.pathCacheIndex][:len(f.Path)]
		f.pathCacheIndex++
		for i := 0; i < len(f.Path); i++ {
			path[i] = f.Path[i]
		}
	} else {
		path = make(ast.Path, len(f.Path))
		copy(path, f.Path)
	}

	f.scalarRequirements = append(f.scalarRequirements, scalarRequirement{
		path:                    path,
		objectName:              objectName,
		fieldRef:                ref,
		fieldType:               fieldType,
		enclosingTypeDefinition: f.EnclosingTypeDefinition,
		fieldTypeDefinitionNode: fieldDefinitionTypeNode,
	})
}

func (f *fieldSelectionMergingVisitor) potentiallySameObject(left, right ast.Node) bool {
	switch {
	case left.Kind == ast.NodeKindInterfaceTypeDefinition || right.Kind == ast.NodeKindInterfaceTypeDefinition:
		return true
	case left.Kind == ast.NodeKindObjectTypeDefinition && right.Kind == ast.NodeKindObjectTypeDefinition:
		return bytes.Equal(f.definition.ObjectTypeDefinitionNameBytes(left.Ref), f.definition.ObjectTypeDefinitionNameBytes(right.Ref))
	default:
		return false
	}
}

func (f *fieldSelectionMergingVisitor) EnterSelectionSet(ref int) {

}

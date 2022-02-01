package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// Fragments validates if the use of fragments in a given document is correct
func Fragments() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := fragmentsVisitor{
			Walker:                     walker,
			fragmentDefinitionsVisited: make([]ast.ByteSlice, 0, 8),
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterLeaveDocumentVisitor(&visitor)
		walker.RegisterEnterFragmentDefinitionVisitor(&visitor)
		walker.RegisterEnterInlineFragmentVisitor(&visitor)
		walker.RegisterEnterFragmentSpreadVisitor(&visitor)
	}
}

type fragmentsVisitor struct {
	*astvisitor.Walker
	operation, definition      *ast.Document
	fragmentDefinitionsVisited []ast.ByteSlice
}

func (f *fragmentsVisitor) EnterFragmentSpread(ref int) {
	if f.Ancestors[0].Kind == ast.NodeKindOperationDefinition {
		spreadName := f.operation.FragmentSpreadNameBytes(ref)
		f.StopWithExternalErr(operationreport.ErrFragmentSpreadFormsCycle(spreadName))
	}
}

func (f *fragmentsVisitor) LeaveDocument(operation, definition *ast.Document) {
	for i := range f.fragmentDefinitionsVisited {
		if !f.operation.FragmentDefinitionIsUsed(f.fragmentDefinitionsVisited[i]) {
			fragmentName := f.fragmentDefinitionsVisited[i]
			f.StopWithExternalErr(operationreport.ErrFragmentDefinedButNotUsed(fragmentName))
			return
		}
	}
}

func (f *fragmentsVisitor) fragmentOnNodeIsAllowed(node ast.Node) bool {
	switch node.Kind {
	case ast.NodeKindObjectTypeDefinition, ast.NodeKindInterfaceTypeDefinition, ast.NodeKindUnionTypeDefinition:
		return true
	default:
		return false
	}
}

func (f *fragmentsVisitor) EnterInlineFragment(ref int) {

	if !f.operation.InlineFragmentHasTypeCondition(ref) {
		return
	}

	typeName := f.operation.InlineFragmentTypeConditionName(ref)

	node, exists := f.definition.Index.FirstNonExtensionNodeByNameBytes(typeName)
	if !exists {
		f.StopWithExternalErr(operationreport.ErrTypeUndefined(typeName))
		return
	}

	if !f.fragmentOnNodeIsAllowed(node) {
		f.StopWithExternalErr(operationreport.ErrInlineFragmentOnTypeDisallowed(typeName))
		return
	}

	if !f.definition.NodeFragmentIsAllowedOnNode(node, f.EnclosingTypeDefinition) {
		enclosingTypeName := f.definition.NodeNameBytes(f.EnclosingTypeDefinition)
		f.StopWithExternalErr(operationreport.ErrInlineFragmentOnTypeMismatchEnclosingType(typeName, enclosingTypeName))
		return
	}
}

func (f *fragmentsVisitor) EnterDocument(operation, definition *ast.Document) {
	f.operation = operation
	f.definition = definition
	f.fragmentDefinitionsVisited = f.fragmentDefinitionsVisited[:0]
}

func (f *fragmentsVisitor) EnterFragmentDefinition(ref int) {

	fragmentDefinitionName := f.operation.FragmentDefinitionNameBytes(ref)
	typeName := f.operation.FragmentDefinitionTypeName(ref)

	node, exists := f.definition.Index.FirstNodeByNameBytes(typeName)
	if !exists {
		f.StopWithExternalErr(operationreport.ErrTypeUndefined(typeName))
		return
	}

	if !f.fragmentOnNodeIsAllowed(node) {
		f.StopWithExternalErr(operationreport.ErrFragmentDefinitionOnTypeDisallowed(fragmentDefinitionName, typeName))
		return
	}

	for i := range f.fragmentDefinitionsVisited {
		if bytes.Equal(fragmentDefinitionName, f.fragmentDefinitionsVisited[i]) {
			f.StopWithExternalErr(operationreport.ErrFragmentDefinitionMustBeUnique(fragmentDefinitionName))
			return
		}
	}

	f.fragmentDefinitionsVisited = append(f.fragmentDefinitionsVisited, fragmentDefinitionName)
}

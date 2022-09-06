package astnormalization

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func mergeInlineFragments(walker *astvisitor.Walker) {
	visitor := mergeInlineFragmentsVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterSelectionSetVisitor(&visitor)
}

type mergeInlineFragmentsVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (m *mergeInlineFragmentsVisitor) EnterDocument(operation, definition *ast.Document) {
	m.operation = operation
	m.definition = definition
}

func (m *mergeInlineFragmentsVisitor) couldInline(set, inlineFragment int) bool {
	if m.operation.InlineFragmentHasDirectives(inlineFragment) {
		return false
	}
	if !m.operation.InlineFragmentHasTypeCondition(inlineFragment) {
		return true
	}
	if bytes.Equal(m.operation.InlineFragmentTypeConditionName(inlineFragment), m.definition.NodeNameBytes(m.EnclosingTypeDefinition)) {
		return true
	}

	inlineFragmentTypeName := m.operation.InlineFragmentTypeConditionName(inlineFragment)
	enclosingTypeName := m.definition.NodeNameBytes(m.EnclosingTypeDefinition)

	return m.definition.TypeDefinitionContainsImplementsInterface(enclosingTypeName, inlineFragmentTypeName)
}

func (m *mergeInlineFragmentsVisitor) resolveInlineFragment(set, index, inlineFragment int) {
	m.operation.ReplaceSelectionOnSelectionSet(set, index, m.operation.InlineFragments[inlineFragment].SelectionSet)
}

func (m *mergeInlineFragmentsVisitor) EnterSelectionSet(ref int) {

	for index, selection := range m.operation.SelectionSets[ref].SelectionRefs {
		if m.operation.Selections[selection].Kind != ast.SelectionKindInlineFragment {
			continue
		}
		inlineFragment := m.operation.Selections[selection].Ref
		if !m.couldInline(ref, inlineFragment) {
			continue
		}
		m.resolveInlineFragment(ref, index, inlineFragment)
		m.RevisitNode()
		return
	}
}

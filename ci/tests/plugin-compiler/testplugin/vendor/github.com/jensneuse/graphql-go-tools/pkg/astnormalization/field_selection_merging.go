package astnormalization

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func mergeFieldSelections(walker *astvisitor.Walker) {
	visitor := fieldSelectionMergeVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterSelectionSetVisitor(&visitor)
}

type fieldSelectionMergeVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (f *fieldSelectionMergeVisitor) EnterDocument(operation, definition *ast.Document) {
	f.operation = operation
}

func (f *fieldSelectionMergeVisitor) fieldsCanMerge(left, right int) bool {
	leftName := f.operation.FieldNameBytes(left)
	rightName := f.operation.FieldNameBytes(right)
	leftAlias := f.operation.FieldAliasBytes(left)
	rightAlias := f.operation.FieldAliasBytes(right)

	if !bytes.Equal(leftName, rightName) || !bytes.Equal(leftAlias, rightAlias) {
		return false
	}

	leftDirectives := f.operation.FieldDirectives(left)
	rightDirectives := f.operation.FieldDirectives(right)

	return f.operation.DirectiveSetsAreEqual(leftDirectives, rightDirectives)
}

func (f *fieldSelectionMergeVisitor) isFieldSelection(ref int) bool {
	return f.operation.Selections[ref].Kind == ast.SelectionKindField
}

func (f *fieldSelectionMergeVisitor) fieldsHaveSelections(left, right int) bool {
	return f.operation.Fields[left].HasSelections && f.operation.Fields[right].HasSelections
}

func (f *fieldSelectionMergeVisitor) removeSelection(set, i int) {
	f.operation.SelectionSets[set].SelectionRefs = append(f.operation.SelectionSets[set].SelectionRefs[:i], f.operation.SelectionSets[set].SelectionRefs[i+1:]...)
}

func (f *fieldSelectionMergeVisitor) mergeFields(left, right int) {
	leftSet := f.operation.Fields[left].SelectionSet
	rightSet := f.operation.Fields[right].SelectionSet
	f.operation.SelectionSets[leftSet].SelectionRefs = append(f.operation.SelectionSets[leftSet].SelectionRefs, f.operation.SelectionSets[rightSet].SelectionRefs...)
	f.operation.Fields[left].Directives.Refs = append(f.operation.Fields[left].Directives.Refs, f.operation.Fields[right].Directives.Refs...)
}

func (f *fieldSelectionMergeVisitor) EnterSelectionSet(ref int) {

	if len(f.operation.SelectionSets[ref].SelectionRefs) < 2 {
		return
	}

	for _, leftSelection := range f.operation.SelectionSets[ref].SelectionRefs {
		if !f.isFieldSelection(leftSelection) {
			continue
		}
		leftField := f.operation.Selections[leftSelection].Ref
		for i, rightSelection := range f.operation.SelectionSets[ref].SelectionRefs {
			if !f.isFieldSelection(rightSelection) {
				continue
			}
			if leftSelection == rightSelection {
				continue
			}
			rightField := f.operation.Selections[rightSelection].Ref
			if !f.fieldsHaveSelections(leftField, rightField) {
				continue
			}
			if !f.fieldsCanMerge(leftField, rightField) {
				continue
			}
			f.removeSelection(ref, i)
			f.mergeFields(leftField, rightField)
			f.RevisitNode()
			return
		}
	}
}

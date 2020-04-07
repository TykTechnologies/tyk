package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func deduplicateFields(walker *astvisitor.Walker) {
	visitor := deduplicateFieldsVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterSelectionSetVisitor(&visitor)
}

type deduplicateFieldsVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (d *deduplicateFieldsVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation = operation
}

func (d *deduplicateFieldsVisitor) EnterSelectionSet(ref int) {
	if len(d.operation.SelectionSets[ref].SelectionRefs) < 2 {
		return
	}

	for a, i := range d.operation.SelectionSets[ref].SelectionRefs {
		if d.operation.Selections[i].Kind != ast.SelectionKindField {
			continue
		}
		left := d.operation.Selections[i].Ref
		if d.operation.Fields[left].HasSelections {
			continue
		}
		for b, j := range d.operation.SelectionSets[ref].SelectionRefs {
			if a == b {
				continue
			}
			if a > b {
				continue
			}
			if d.operation.Selections[j].Kind != ast.SelectionKindField {
				continue
			}
			right := d.operation.Selections[j].Ref
			if d.operation.Fields[right].HasSelections {
				continue
			}
			if d.operation.FieldsAreEqualFlat(left, right) {
				d.operation.RemoveFromSelectionSet(ref, b)
				d.RevisitNode()
				return
			}
		}
	}
}

package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// DirectivesAreUniquePerLocation validates if directives are unique per location
func DirectivesAreUniquePerLocation() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := directivesAreUniquePerLocationVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterDirectiveVisitor(&visitor)
	}
}

type directivesAreUniquePerLocationVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (d *directivesAreUniquePerLocationVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation = operation
	d.definition = definition
}

func (d *directivesAreUniquePerLocationVisitor) EnterDirective(ref int) {

	directiveName := d.operation.DirectiveNameBytes(ref)
	directives := d.operation.NodeDirectives(d.Ancestors[len(d.Ancestors)-1])

	for _, j := range directives {
		if j == ref {
			continue
		}
		if bytes.Equal(directiveName, d.operation.DirectiveNameBytes(j)) {
			d.StopWithExternalErr(operationreport.ErrDirectiveMustBeUniquePerLocation(directiveName))
			return
		}
	}
}

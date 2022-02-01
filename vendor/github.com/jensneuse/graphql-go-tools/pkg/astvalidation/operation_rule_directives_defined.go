package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// DirectivesAreDefined validates if used directives are defined
func DirectivesAreDefined() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := directivesAreDefinedVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterDirectiveVisitor(&visitor)
	}
}

type directivesAreDefinedVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (d *directivesAreDefinedVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation = operation
	d.definition = definition
}

func (d *directivesAreDefinedVisitor) EnterDirective(ref int) {

	directiveName := d.operation.DirectiveNameBytes(ref)
	definition, exists := d.definition.Index.FirstNodeByNameBytes(directiveName)

	if !exists || definition.Kind != ast.NodeKindDirectiveDefinition {
		d.StopWithExternalErr(operationreport.ErrDirectiveUndefined(directiveName))
		return
	}
}

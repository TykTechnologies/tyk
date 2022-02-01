package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// DirectivesAreInValidLocations validates if directives are used in the right place
func DirectivesAreInValidLocations() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := directivesAreInValidLocationsVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterDirectiveVisitor(&visitor)
	}
}

type directivesAreInValidLocationsVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (d *directivesAreInValidLocationsVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation = operation
	d.definition = definition
}

func (d *directivesAreInValidLocationsVisitor) EnterDirective(ref int) {

	directiveName := d.operation.DirectiveNameBytes(ref)
	definition, exists := d.definition.Index.FirstNodeByNameBytes(directiveName)

	if !exists || definition.Kind != ast.NodeKindDirectiveDefinition {
		return // not defined, skip
	}

	ancestor := d.Ancestors[len(d.Ancestors)-1]

	if !d.directiveDefinitionContainsNodeLocation(definition.Ref, ancestor) {
		ancestorKindName := d.operation.NodeKindNameBytes(ancestor)
		d.StopWithExternalErr(operationreport.ErrDirectiveNotAllowedOnNode(directiveName, ancestorKindName))
		return
	}
}

func (d *directivesAreInValidLocationsVisitor) directiveDefinitionContainsNodeLocation(definition int, node ast.Node) bool {

	nodeDirectiveLocation, err := d.operation.NodeDirectiveLocation(node)
	if err != nil {
		return false
	}

	return d.definition.DirectiveDefinitions[definition].DirectiveLocations.Get(nodeDirectiveLocation)
}

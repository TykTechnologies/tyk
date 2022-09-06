package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendScalarTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendScalarTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterScalarTypeExtensionVisitor(&visitor)
}

type extendScalarTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendScalarTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendScalarTypeDefinitionVisitor) EnterScalarTypeExtension(ref int) {

	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.ScalarTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindScalarTypeDefinition {
			continue
		}
		e.operation.ExtendScalarTypeDefinitionByScalarTypeExtension(nodes[i].Ref, ref)
		return
	}

	e.operation.ImportAndExtendScalarTypeDefinitionByScalarTypeExtension(ref)
}

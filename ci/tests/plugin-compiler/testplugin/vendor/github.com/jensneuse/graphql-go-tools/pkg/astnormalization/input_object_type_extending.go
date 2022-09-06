package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendInputObjectTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendInputObjectTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterInputObjectTypeExtensionVisitor(&visitor)
}

type extendInputObjectTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendInputObjectTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendInputObjectTypeDefinitionVisitor) EnterInputObjectTypeExtension(ref int) {

	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.InputObjectTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindInputObjectTypeDefinition {
			continue
		}
		e.operation.ExtendInputObjectTypeDefinitionByInputObjectTypeExtension(nodes[i].Ref, ref)
		return
	}

	e.operation.ImportAndExtendInputObjectTypeDefinitionByInputObjectTypeExtension(ref)
}

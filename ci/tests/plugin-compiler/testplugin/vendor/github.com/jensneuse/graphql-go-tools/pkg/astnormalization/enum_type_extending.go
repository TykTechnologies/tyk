package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendEnumTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendEnumTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterEnumTypeExtensionVisitor(&visitor)
}

type extendEnumTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendEnumTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendEnumTypeDefinitionVisitor) EnterEnumTypeExtension(ref int) {
	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.EnumTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindEnumTypeDefinition {
			continue
		}
		e.operation.ExtendEnumTypeDefinitionByEnumTypeExtension(nodes[i].Ref, ref)
		return
	}

	e.operation.ImportAndExtendEnumTypeDefinitionByEnumTypeExtension(ref)
}

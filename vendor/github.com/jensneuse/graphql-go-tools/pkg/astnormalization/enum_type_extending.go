package astnormalization

import (
	"github.com/cespare/xxhash"
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

	baseNode, exists := e.operation.Index.Nodes[xxhash.Sum64(e.operation.EnumTypeExtensionNameBytes(ref))]
	if !exists {
		return
	}

	if baseNode.Kind != ast.NodeKindEnumTypeDefinition {
		return
	}

	e.operation.ExtendEnumTypeDefinitionByEnumTypeExtension(baseNode.Ref, ref)
}

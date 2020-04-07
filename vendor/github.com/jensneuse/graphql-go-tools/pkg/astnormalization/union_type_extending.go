package astnormalization

import (
	"github.com/cespare/xxhash"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendUnionTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendUnionTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterUnionTypeExtensionVisitor(&visitor)
}

type extendUnionTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendUnionTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendUnionTypeDefinitionVisitor) EnterUnionTypeExtension(ref int) {

	baseNode, exists := e.operation.Index.Nodes[xxhash.Sum64(e.operation.UnionTypeExtensionNameBytes(ref))]
	if !exists {
		return
	}

	if baseNode.Kind != ast.NodeKindUnionTypeDefinition {
		return
	}

	e.operation.ExtendUnionTypeDefinitionByUnionTypeExtension(baseNode.Ref, ref)
}

package astnormalization

import (
	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendObjectTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendObjectTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterObjectTypeExtensionVisitor(&visitor)
}

type extendObjectTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendObjectTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendObjectTypeDefinitionVisitor) EnterObjectTypeExtension(ref int) {

	baseNode, exists := e.operation.Index.Nodes[xxhash.Sum64(e.operation.ObjectTypeExtensionNameBytes(ref))]
	if !exists {
		return
	}

	if baseNode.Kind != ast.NodeKindObjectTypeDefinition {
		return
	}

	e.operation.ExtendObjectTypeDefinitionByObjectTypeExtension(baseNode.Ref, ref)
}

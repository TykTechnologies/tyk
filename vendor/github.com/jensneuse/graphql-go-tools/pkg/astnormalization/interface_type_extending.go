package astnormalization

import (
	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extendInterfaceTypeDefinition(walker *astvisitor.Walker) {
	visitor := extendInterfaceTypeDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterInterfaceTypeExtensionVisitor(&visitor)
}

type extendInterfaceTypeDefinitionVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (e *extendInterfaceTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendInterfaceTypeDefinitionVisitor) EnterInterfaceTypeExtension(ref int) {

	baseNode, exists := e.operation.Index.Nodes[xxhash.Sum64(e.operation.InterfaceTypeExtensionNameBytes(ref))]
	if !exists {
		return
	}

	if baseNode.Kind != ast.NodeKindInterfaceTypeDefinition {
		return
	}

	e.operation.ExtendInterfaceTypeDefinitionByInterfaceTypeExtension(baseNode.Ref, ref)
}

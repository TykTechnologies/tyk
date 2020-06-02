package astnormalization

import (
	"github.com/cespare/xxhash"

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

	baseNode, exists := e.operation.Index.Nodes[xxhash.Sum64(e.operation.ScalarTypeExtensionNameBytes(ref))]
	if !exists {
		return
	}

	if baseNode.Kind != ast.NodeKindScalarTypeDefinition {
		return
	}

	e.operation.ExtendScalarTypeDefinitionByScalarTypeExtension(baseNode.Ref, ref)
}

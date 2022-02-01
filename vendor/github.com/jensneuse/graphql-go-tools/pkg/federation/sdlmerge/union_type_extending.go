package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newExtendUnionTypeDefinition() *extendUnionTypeDefinitionVisitor {
	return &extendUnionTypeDefinitionVisitor{}
}

type extendUnionTypeDefinitionVisitor struct {
	operation *ast.Document
}

func (e *extendUnionTypeDefinitionVisitor) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(e)
	walker.RegisterEnterUnionTypeExtensionVisitor(e)
}

func (e *extendUnionTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendUnionTypeDefinitionVisitor) EnterUnionTypeExtension(ref int) {

	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.UnionTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindUnionTypeDefinition {
			continue
		}
		e.operation.ExtendUnionTypeDefinitionByUnionTypeExtension(nodes[i].Ref, ref)
		return
	}
}

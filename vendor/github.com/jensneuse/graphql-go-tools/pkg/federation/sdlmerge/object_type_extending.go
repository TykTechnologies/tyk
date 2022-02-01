package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newExtendObjectTypeDefinition() *extendObjectTypeDefinitionVisitor {
	return &extendObjectTypeDefinitionVisitor{}
}

type extendObjectTypeDefinitionVisitor struct {
	operation *ast.Document
}

func (e *extendObjectTypeDefinitionVisitor) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(e)
	walker.RegisterEnterObjectTypeExtensionVisitor(e)
}

func (e *extendObjectTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendObjectTypeDefinitionVisitor) EnterObjectTypeExtension(ref int) {
	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.ObjectTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindObjectTypeDefinition {
			continue
		}
		e.operation.ExtendObjectTypeDefinitionByObjectTypeExtension(nodes[i].Ref, ref)
		return
	}
}

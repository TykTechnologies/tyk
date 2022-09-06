package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newExtendInterfaceTypeDefinition() *extendInterfaceTypeDefinitionVisitor {
	return &extendInterfaceTypeDefinitionVisitor{}
}

type extendInterfaceTypeDefinitionVisitor struct {
	operation *ast.Document
}

func (e *extendInterfaceTypeDefinitionVisitor) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(e)
	walker.RegisterEnterInterfaceTypeExtensionVisitor(e)
}

func (e *extendInterfaceTypeDefinitionVisitor) EnterDocument(operation, definition *ast.Document) {
	e.operation = operation
}

func (e *extendInterfaceTypeDefinitionVisitor) EnterInterfaceTypeExtension(ref int) {

	nodes, exists := e.operation.Index.NodesByNameBytes(e.operation.InterfaceTypeExtensionNameBytes(ref))
	if !exists {
		return
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindInterfaceTypeDefinition {
			continue
		}
		e.operation.ExtendInterfaceTypeDefinitionByInterfaceTypeExtension(nodes[i].Ref, ref)
		return
	}
}

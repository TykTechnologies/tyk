package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

type FragmentDefinitionRemoval struct {
}

func removeFragmentDefinitions(walker *astvisitor.Walker) {
	visitor := removeFragmentDefinitionsVisitor{}
	walker.RegisterLeaveDocumentVisitor(visitor)
}

type removeFragmentDefinitionsVisitor struct {
}

func (r removeFragmentDefinitionsVisitor) LeaveDocument(operation, definition *ast.Document) {
	for i := range operation.RootNodes {
		if operation.RootNodes[i].Kind == ast.NodeKindFragmentDefinition {
			operation.RootNodes[i].Kind = ast.NodeKindUnknown
		}
	}
}

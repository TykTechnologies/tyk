package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// DocumentContainsExecutableOperation validates if the document actually contains an executable Operation
func DocumentContainsExecutableOperation() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &documentContainsExecutableOperation{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(visitor)
	}
}

type documentContainsExecutableOperation struct {
	*astvisitor.Walker
}

func (d *documentContainsExecutableOperation) EnterDocument(operation, definition *ast.Document) {
	if len(operation.RootNodes) == 0 {
		d.StopWithExternalErr(operationreport.ErrDocumentDoesntContainExecutableOperation())
		return
	}
	for i := range operation.RootNodes {
		if operation.RootNodes[i].Kind == ast.NodeKindOperationDefinition {
			return
		}
	}
	d.StopWithExternalErr(operationreport.ErrDocumentDoesntContainExecutableOperation())
}

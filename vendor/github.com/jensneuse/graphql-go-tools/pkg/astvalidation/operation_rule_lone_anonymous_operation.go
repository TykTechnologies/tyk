package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// LoneAnonymousOperation validates if anonymous operations are alone in a given document.
func LoneAnonymousOperation() Rule {
	return func(walker *astvisitor.Walker) {
		walker.RegisterEnterDocumentVisitor(&loneAnonymousOperationVisitor{walker})
	}
}

type loneAnonymousOperationVisitor struct {
	*astvisitor.Walker
}

func (l *loneAnonymousOperationVisitor) EnterDocument(operation, definition *ast.Document) {
	if len(operation.OperationDefinitions) <= 1 {
		return
	}

	for i := range operation.OperationDefinitions {
		if operation.OperationDefinitions[i].Name.Length() == 0 {
			l.StopWithExternalErr(operationreport.ErrAnonymousOperationMustBeTheOnlyOperationInDocument())
			return
		}
	}
}

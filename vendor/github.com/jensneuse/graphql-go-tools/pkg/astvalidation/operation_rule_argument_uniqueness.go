package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// ArgumentUniqueness validates if arguments are unique
func ArgumentUniqueness() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := argumentUniquenessVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterArgumentVisitor(&visitor)
	}
}

type argumentUniquenessVisitor struct {
	*astvisitor.Walker
	operation *ast.Document
}

func (a *argumentUniquenessVisitor) EnterDocument(operation, definition *ast.Document) {
	a.operation = operation
}

func (a *argumentUniquenessVisitor) EnterArgument(ref int) {

	argumentName := a.operation.ArgumentNameBytes(ref)
	argumentsAfter := a.operation.ArgumentsAfter(a.Ancestors[len(a.Ancestors)-1], ref)

	for _, i := range argumentsAfter {
		if bytes.Equal(argumentName, a.operation.ArgumentNameBytes(i)) {
			a.StopWithExternalErr(operationreport.ErrArgumentMustBeUnique(argumentName))
			return
		}
	}
}

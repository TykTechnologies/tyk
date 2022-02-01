package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// OperationNameUniqueness validates if all operation names are unique
func OperationNameUniqueness() Rule {
	return func(walker *astvisitor.Walker) {
		walker.RegisterEnterDocumentVisitor(&operationNameUniquenessVisitor{walker})
	}
}

type operationNameUniquenessVisitor struct {
	*astvisitor.Walker
}

func (o *operationNameUniquenessVisitor) EnterDocument(operation, definition *ast.Document) {
	if len(operation.OperationDefinitions) <= 1 {
		return
	}

	for i := range operation.OperationDefinitions {
		for k := range operation.OperationDefinitions {
			if i == k || i > k {
				continue
			}

			left := operation.OperationDefinitions[i].Name
			right := operation.OperationDefinitions[k].Name

			if ast.ByteSliceEquals(left, operation.Input, right, operation.Input) {
				operationName := operation.Input.ByteSlice(operation.OperationDefinitions[i].Name)
				o.StopWithExternalErr(operationreport.ErrOperationNameMustBeUnique(operationName))
				return
			}
		}
	}
}

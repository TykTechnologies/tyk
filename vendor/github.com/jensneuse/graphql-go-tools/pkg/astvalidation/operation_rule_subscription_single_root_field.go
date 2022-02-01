package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// SubscriptionSingleRootField validates if subscriptions have a single root field
func SubscriptionSingleRootField() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := subscriptionSingleRootFieldVisitor{walker}
		walker.RegisterEnterDocumentVisitor(&visitor)
	}
}

type subscriptionSingleRootFieldVisitor struct {
	*astvisitor.Walker
}

func (s *subscriptionSingleRootFieldVisitor) EnterDocument(operation, definition *ast.Document) {
	for i := range operation.OperationDefinitions {
		if operation.OperationDefinitions[i].OperationType == ast.OperationTypeSubscription {
			selections := len(operation.SelectionSets[operation.OperationDefinitions[i].SelectionSet].SelectionRefs)
			if selections > 1 {
				subscriptionName := operation.Input.ByteSlice(operation.OperationDefinitions[i].Name)
				s.StopWithExternalErr(operationreport.ErrSubscriptionMustOnlyHaveOneRootSelection(subscriptionName))
				return
			} else if selections == 1 {
				ref := operation.SelectionSets[operation.OperationDefinitions[i].SelectionSet].SelectionRefs[0]
				if operation.Selections[ref].Kind == ast.SelectionKindField {
					return
				}
			}
		}
	}
}

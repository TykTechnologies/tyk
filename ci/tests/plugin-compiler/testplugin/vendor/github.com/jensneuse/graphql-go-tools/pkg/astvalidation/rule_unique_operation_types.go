package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func UniqueOperationTypes() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &uniqueOperationTypesVisitor{
			Walker: walker,
		}

		walker.RegisterEnterDocumentVisitor(visitor)
		walker.RegisterEnterRootOperationTypeDefinitionVisitor(visitor)
	}
}

type uniqueOperationTypesVisitor struct {
	*astvisitor.Walker
	definition            *ast.Document
	queryIsDefined        bool
	mutationIsDefined     bool
	subscriptionIsDefined bool
}

func (u *uniqueOperationTypesVisitor) EnterDocument(operation, definition *ast.Document) {
	u.definition = operation
	u.queryIsDefined = false
	u.mutationIsDefined = false
	u.subscriptionIsDefined = false
}

func (u *uniqueOperationTypesVisitor) EnterRootOperationTypeDefinition(ref int) {
	operationType := u.definition.RootOperationTypeDefinitions[ref].OperationType
	switch operationType {
	case ast.OperationTypeQuery:
		if u.queryIsDefined {
			u.Report.AddExternalError(operationreport.ErrOnlyOneQueryTypeAllowed())
		}
		u.queryIsDefined = true
	case ast.OperationTypeMutation:
		if u.mutationIsDefined {
			u.Report.AddExternalError(operationreport.ErrOnlyOneMutationTypeAllowed())
		}
		u.mutationIsDefined = true
	case ast.OperationTypeSubscription:
		if u.subscriptionIsDefined {
			u.Report.AddExternalError(operationreport.ErrOnlyOneSubscriptionTypeAllowed())
		}
		u.subscriptionIsDefined = true
	}
}

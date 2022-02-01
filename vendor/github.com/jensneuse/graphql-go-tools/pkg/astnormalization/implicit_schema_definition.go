package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

const (
	implicitQueryTypeName        = "Query"
	implicitMutationTypeName     = "Mutation"
	implicitSubscriptionTypeName = "Subscription"
)

func implicitSchemaDefinition(walker *astvisitor.Walker) {
	visitor := implicitSchemaDefinitionVisitor{
		Walker: walker,
	}
	walker.RegisterLeaveDocumentVisitor(&visitor)
}

type implicitSchemaDefinitionVisitor struct {
	*astvisitor.Walker
}

func (i *implicitSchemaDefinitionVisitor) LeaveDocument(operation, definition *ast.Document) {
	queryNodeName := i.nodeName(implicitQueryTypeName, operation)
	mutationNodeName := i.nodeName(implicitMutationTypeName, operation)
	subscriptionNodeName := i.nodeName(implicitSubscriptionTypeName, operation)

	schemaDefinitionRef := operation.SchemaDefinitionRef()
	if schemaDefinitionRef == ast.InvalidRef {
		operation.ImportSchemaDefinition(queryNodeName, mutationNodeName, subscriptionNodeName)
		return
	}

	if len(operation.SchemaDefinitions[schemaDefinitionRef].RootOperationTypeDefinitions.Refs) > 0 {
		return
	}

	operation.ReplaceRootOperationTypesOfSchemaDefinition(schemaDefinitionRef, queryNodeName, mutationNodeName, subscriptionNodeName)
}

func (i *implicitSchemaDefinitionVisitor) nodeName(operationTypeName string, operation *ast.Document) string {
	nodes, ok := operation.Index.NodesByNameStr(operationTypeName)
	if !ok {
		return ""
	}

	for i := range nodes {
		if nodes[i].Kind != ast.NodeKindObjectTypeDefinition {
			continue
		}

		return operationTypeName
	}

	return ""
}

package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

/*
type Query {...}
type Mutation {...}
type Subscription {...}

will be,

extend type Query {...}
extend type Mutation {...}
extend type Subscription {...}

this also works if root types are defined in schema{...} with other names.
root types are left unmodified if they have no fields, directives or implements any interface.
*/
type implicitExtendRootOperationVisitor struct {
	operation *ast.Document
}

func implicitExtendRootOperation(walker *astvisitor.Walker) {
	v := &implicitExtendRootOperationVisitor{}
	walker.RegisterEnterDocumentVisitor(v)
	walker.RegisterEnterObjectTypeDefinitionVisitor(v)
}

func (v *implicitExtendRootOperationVisitor) EnterDocument(operation, _ *ast.Document) {
	v.operation = operation
}

func (v *implicitExtendRootOperationVisitor) EnterObjectTypeDefinition(ref int) {
	node := v.operation.ObjectTypeDefinitions[ref]
	if !(node.HasFieldDefinitions || node.HasDirectives) {
		return
	}
	switch v.operation.ObjectTypeDefinitionNameString(ref) {
	case implicitQueryTypeName, implicitMutationTypeName, implicitSubscriptionTypeName,
		v.operation.Index.QueryTypeName.String(), v.operation.Index.MutationTypeName.String(), v.operation.Index.SubscriptionTypeName.String():
		for i := range v.operation.RootNodes {
			if v.operation.RootNodes[i].Ref == ref && v.operation.RootNodes[i].Kind == ast.NodeKindObjectTypeDefinition {
				// give this node a new NodeKind of ObjectTypeExtension
				newRef := v.operation.AddObjectTypeDefinitionExtension(ast.ObjectTypeExtension{ObjectTypeDefinition: node})
				// reflect changes inside the root nodes
				v.operation.UpdateRootNode(i, newRef, ast.NodeKindObjectTypeExtension)
				break
			}
		}
	}
}

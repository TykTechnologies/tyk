package astvalidation

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func RequireDefinedTypesForExtensions() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &requireDefinedTypesForExtensionsVisitor{
			Walker: walker,
		}

		walker.RegisterEnterDocumentVisitor(visitor)
		walker.RegisterEnterScalarTypeExtensionVisitor(visitor)
		walker.RegisterEnterObjectTypeExtensionVisitor(visitor)
		walker.RegisterEnterInterfaceTypeExtensionVisitor(visitor)
		walker.RegisterEnterUnionTypeExtensionVisitor(visitor)
		walker.RegisterEnterEnumTypeExtensionVisitor(visitor)
		walker.RegisterEnterInputObjectTypeExtensionVisitor(visitor)
	}
}

type requireDefinedTypesForExtensionsVisitor struct {
	*astvisitor.Walker
	definition *ast.Document
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterDocument(operation, definition *ast.Document) {
	r.definition = operation
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterScalarTypeExtension(ref int) {
	name := r.definition.ScalarTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindScalarTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrScalarTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterObjectTypeExtension(ref int) {
	name := r.definition.ObjectTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindObjectTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterInterfaceTypeExtension(ref int) {
	name := r.definition.InterfaceTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindInterfaceTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrInterfaceTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterUnionTypeExtension(ref int) {
	name := r.definition.UnionTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindUnionTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrUnionTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterEnumTypeExtension(ref int) {
	name := r.definition.EnumTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindEnumTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrEnumTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) EnterInputObjectTypeExtension(ref int) {
	name := r.definition.InputObjectTypeExtensionNameBytes(ref)
	if !r.extensionIsValidForNodeKind(name, ast.NodeKindInputObjectTypeDefinition) {
		r.Report.AddExternalError(operationreport.ErrInputObjectTypeUndefined(name))
	}
}

func (r *requireDefinedTypesForExtensionsVisitor) extensionIsValidForNodeKind(name ast.ByteSlice, definitionNodeKind ast.NodeKind) bool {
	nodes, exists := r.definition.Index.NodesByNameBytes(name)
	if !exists {
		return true
	}

	for i := 0; i < len(nodes); i++ {
		if nodes[i].Kind == definitionNodeKind {
			return true
		}
	}

	return false
}

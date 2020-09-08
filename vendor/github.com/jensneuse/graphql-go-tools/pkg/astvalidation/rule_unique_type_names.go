package astvalidation

import (
	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func UniqueTypeNames() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &uniqueTypeNamesVisitor{
			Walker: walker,
		}

		walker.RegisterEnterDocumentVisitor(visitor)
		walker.RegisterEnterObjectTypeDefinitionVisitor(visitor)
		walker.RegisterEnterScalarTypeDefinitionVisitor(visitor)
		walker.RegisterEnterInterfaceTypeDefinitionVisitor(visitor)
		walker.RegisterEnterUnionTypeDefinitionVisitor(visitor)
		walker.RegisterEnterEnumTypeDefinitionVisitor(visitor)
		walker.RegisterEnterInputObjectTypeDefinitionVisitor(visitor)
	}
}

type uniqueTypeNamesVisitor struct {
	*astvisitor.Walker
	definition          *ast.Document
	usedTypeNamesAsHash map[uint64]bool
}

func (u *uniqueTypeNamesVisitor) EnterDocument(operation, definition *ast.Document) {
	u.definition = operation
	u.usedTypeNamesAsHash = make(map[uint64]bool)
}

func (u *uniqueTypeNamesVisitor) EnterObjectTypeDefinition(ref int) {
	typeName := u.definition.ObjectTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) EnterScalarTypeDefinition(ref int) {
	typeName := u.definition.ScalarTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) EnterInterfaceTypeDefinition(ref int) {
	typeName := u.definition.InterfaceTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) EnterUnionTypeDefinition(ref int) {
	typeName := u.definition.UnionTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) EnterEnumTypeDefinition(ref int) {
	typeName := u.definition.EnumTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) EnterInputObjectTypeDefinition(ref int) {
	typeName := u.definition.InputObjectTypeDefinitionNameBytes(ref)
	u.checkTypeName(typeName)
}

func (u *uniqueTypeNamesVisitor) checkTypeName(typeName ast.ByteSlice) {
	hashedTypeName := xxhash.Sum64(typeName)
	if u.usedTypeNamesAsHash[hashedTypeName] {
		u.Report.AddExternalError(operationreport.ErrTypeNameMustBeUnique(typeName))
		return
	}
	u.usedTypeNamesAsHash[hashedTypeName] = true
}

package astvalidation

import (
	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func KnownTypeNames() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &knownTypeNamesVisitor{
			Walker: walker,
		}

		walker.RegisterDocumentVisitor(visitor)
		walker.RegisterEnterRootOperationTypeDefinitionVisitor(visitor)
		walker.RegisterEnterFieldDefinitionVisitor(visitor)
		walker.RegisterEnterUnionMemberTypeVisitor(visitor)
		walker.RegisterEnterInputValueDefinitionVisitor(visitor)
		walker.RegisterEnterObjectTypeDefinitionVisitor(visitor)
		walker.RegisterEnterInterfaceTypeDefinitionVisitor(visitor)
		walker.RegisterEnterScalarTypeDefinitionVisitor(visitor)
		walker.RegisterEnterUnionTypeDefinitionVisitor(visitor)
		walker.RegisterEnterInputObjectTypeDefinitionVisitor(visitor)
		walker.RegisterEnterEnumTypeDefinitionVisitor(visitor)
	}
}

type knownTypeNamesVisitor struct {
	*astvisitor.Walker
	definition           *ast.Document
	definedTypeNameHashs map[uint64]bool
	referencedTypeNames  map[uint64][]byte
}

func (u *knownTypeNamesVisitor) EnterDocument(operation, definition *ast.Document) {
	u.definition = operation
	u.definedTypeNameHashs = make(map[uint64]bool)
	u.referencedTypeNames = make(map[uint64][]byte)
}

func (u *knownTypeNamesVisitor) LeaveDocument(operation, definition *ast.Document) {
	for referencedTypeNameHash, referencedTypeName := range u.referencedTypeNames {
		if !u.definedTypeNameHashs[referencedTypeNameHash] {
			u.Report.AddExternalError(operationreport.ErrTypeUndefined(referencedTypeName))
			continue
		}
	}

}

func (u *knownTypeNamesVisitor) EnterRootOperationTypeDefinition(ref int) {
	referencedTypeName := u.definition.Input.ByteSlice(u.definition.RootOperationTypeDefinitions[ref].NamedType.Name)
	u.saveReferencedTypeName(referencedTypeName)
	u.saveReferencedTypeName(referencedTypeName)
}

func (u *knownTypeNamesVisitor) EnterFieldDefinition(ref int) {
	referencedTypeRef := u.definition.FieldDefinitions[ref].Type
	referencedTypeName := u.definition.TypeNameBytes(referencedTypeRef)
	u.saveReferencedTypeName(referencedTypeName)
}

func (u *knownTypeNamesVisitor) EnterUnionMemberType(ref int) {
	referencedTypeName := u.definition.TypeNameBytes(ref)
	u.saveReferencedTypeName(referencedTypeName)
}

func (u *knownTypeNamesVisitor) EnterInputValueDefinition(ref int) {
	referencedTypeRef := u.definition.InputValueDefinitions[ref].Type
	referencedTypeName := u.definition.TypeNameBytes(referencedTypeRef)
	u.saveReferencedTypeName(referencedTypeName)
}

func (u *knownTypeNamesVisitor) EnterObjectTypeDefinition(ref int) {
	typeName := u.definition.ObjectTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) EnterInterfaceTypeDefinition(ref int) {
	typeName := u.definition.InterfaceTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) EnterScalarTypeDefinition(ref int) {
	typeName := u.definition.ScalarTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) EnterUnionTypeDefinition(ref int) {
	typeName := u.definition.UnionTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) EnterInputObjectTypeDefinition(ref int) {
	typeName := u.definition.InputObjectTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) EnterEnumTypeDefinition(ref int) {
	typeName := u.definition.EnumTypeDefinitionNameBytes(ref)
	u.saveTypeName(typeName)
}

func (u *knownTypeNamesVisitor) saveTypeName(typeName ast.ByteSlice) {
	u.definedTypeNameHashs[xxhash.Sum64(typeName)] = true
}

func (u *knownTypeNamesVisitor) saveReferencedTypeName(referencedTypeName ast.ByteSlice) {
	if len(referencedTypeName) == 0 {
		return
	}
	u.referencedTypeNames[xxhash.Sum64(referencedTypeName)] = referencedTypeName
}

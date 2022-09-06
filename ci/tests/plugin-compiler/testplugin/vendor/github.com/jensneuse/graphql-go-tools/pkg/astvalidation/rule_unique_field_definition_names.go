package astvalidation

import (
	"bytes"

	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type hashedFieldNames map[uint64]bool

func UniqueFieldDefinitionNames() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &uniqueFieldDefinitionNamesVisitor{
			Walker: walker,
		}

		walker.RegisterEnterDocumentVisitor(visitor)
		walker.RegisterEnterFieldDefinitionVisitor(visitor)
		walker.RegisterEnterInputValueDefinitionVisitor(visitor)
		walker.RegisterObjectTypeDefinitionVisitor(visitor)
		walker.RegisterObjectTypeExtensionVisitor(visitor)
		walker.RegisterInterfaceTypeDefinitionVisitor(visitor)
		walker.RegisterInterfaceTypeExtensionVisitor(visitor)
		walker.RegisterInputObjectTypeDefinitionVisitor(visitor)
		walker.RegisterInputObjectTypeExtensionVisitor(visitor)
	}
}

type uniqueFieldDefinitionNamesVisitor struct {
	*astvisitor.Walker
	definition          *ast.Document
	currentTypeName     ast.ByteSlice
	currentTypeNameHash uint64
	currentTypeKind     ast.NodeKind
	usedFieldNames      map[uint64]hashedFieldNames // map of hashed type names containing a map of hashed field names
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterDocument(operation, definition *ast.Document) {
	u.definition = operation
	u.currentTypeName = u.currentTypeName[:0]
	u.currentTypeNameHash = 0
	u.currentTypeKind = ast.NodeKindUnknown
	u.usedFieldNames = make(map[uint64]hashedFieldNames)
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterFieldDefinition(ref int) {
	fieldName := u.definition.FieldDefinitionNameBytes(ref)
	u.checkField(fieldName)
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterInputValueDefinition(ref int) {
	if u.currentTypeKind != ast.NodeKindInputObjectTypeDefinition && u.currentTypeKind != ast.NodeKindInputObjectTypeExtension {
		return
	}

	name := u.definition.InputValueDefinitionNameBytes(ref)
	u.checkField(name)
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterObjectTypeDefinition(ref int) {
	typeName := u.definition.ObjectTypeDefinitionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindObjectTypeDefinition)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveObjectTypeDefinition(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterObjectTypeExtension(ref int) {
	typeName := u.definition.ObjectTypeExtensionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindObjectTypeExtension)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveObjectTypeExtension(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterInterfaceTypeDefinition(ref int) {
	typeName := u.definition.InterfaceTypeDefinitionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindInterfaceTypeDefinition)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveInterfaceTypeDefinition(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterInterfaceTypeExtension(ref int) {
	typeName := u.definition.InterfaceTypeExtensionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindInterfaceTypeExtension)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveInterfaceTypeExtension(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterInputObjectTypeDefinition(ref int) {
	typeName := u.definition.InputObjectTypeDefinitionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindObjectTypeDefinition)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveInputObjectTypeDefinition(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) EnterInputObjectTypeExtension(ref int) {
	typeName := u.definition.InputObjectTypeExtensionNameBytes(ref)
	u.setCurrentTypeName(typeName, ast.NodeKindInputObjectTypeExtension)
}

func (u *uniqueFieldDefinitionNamesVisitor) LeaveInputObjectTypeExtension(ref int) {
	u.unsetCurrentTypeName()
}

func (u *uniqueFieldDefinitionNamesVisitor) setCurrentTypeName(typeName ast.ByteSlice, kind ast.NodeKind) {
	if bytes.HasPrefix(typeName, []byte("__")) { // ignore graphql reserved types
		return
	}

	u.currentTypeName = typeName
	u.currentTypeNameHash = xxhash.Sum64(typeName)
	u.currentTypeKind = kind
}

func (u *uniqueFieldDefinitionNamesVisitor) unsetCurrentTypeName() {
	u.currentTypeName = u.currentTypeName[:0]
	u.currentTypeNameHash = 0
	u.currentTypeKind = ast.NodeKindUnknown
}

func (u *uniqueFieldDefinitionNamesVisitor) checkField(fieldName ast.ByteSlice) {
	if bytes.HasPrefix(fieldName, []byte("__")) { // don't validate graphql reserved fields
		return
	}

	if len(u.currentTypeName) == 0 || u.currentTypeNameHash == 0 || u.currentTypeKind == ast.NodeKindUnknown {
		return
	}

	fieldNames, ok := u.usedFieldNames[u.currentTypeNameHash]
	if !ok {
		fieldNames = make(hashedFieldNames)
	}

	if fieldNames[xxhash.Sum64(fieldName)] {
		u.Report.AddExternalError(operationreport.ErrFieldNameMustBeUniqueOnType(fieldName, u.currentTypeName))
		return
	}

	fieldNames[xxhash.Sum64(fieldName)] = true
	u.usedFieldNames[u.currentTypeNameHash] = fieldNames
}

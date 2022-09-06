package astvalidation

import (
	"github.com/cespare/xxhash"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type hashedEnumValueNames map[uint64]bool

func UniqueEnumValueNames() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := &uniqueEnumValueNamesVisitor{
			Walker: walker,
		}

		walker.RegisterEnterDocumentVisitor(visitor)
		walker.RegisterEnterEnumValueDefinitionVisitor(visitor)
		walker.RegisterEnumTypeDefinitionVisitor(visitor)
		walker.RegisterEnumTypeExtensionVisitor(visitor)
	}
}

type uniqueEnumValueNamesVisitor struct {
	*astvisitor.Walker
	definition      *ast.Document
	currentEnumName ast.ByteSlice
	currentEnumHash uint64
	usedEnumValues  map[uint64]hashedEnumValueNames
}

func (u *uniqueEnumValueNamesVisitor) EnterDocument(operation, definition *ast.Document) {
	u.definition = operation
	u.currentEnumName = u.currentEnumName[:0]
	u.currentEnumHash = 0
	u.usedEnumValues = make(map[uint64]hashedEnumValueNames)
}

func (u *uniqueEnumValueNamesVisitor) EnterEnumValueDefinition(ref int) {
	enumValueName := u.definition.EnumValueDefinitionNameBytes(ref)
	u.checkEnumValueName(enumValueName)
}

func (u *uniqueEnumValueNamesVisitor) EnterEnumTypeDefinition(ref int) {
	enumName := u.definition.EnumTypeDefinitionNameBytes(ref)
	u.setCurrentEnum(enumName)
}

func (u *uniqueEnumValueNamesVisitor) LeaveEnumTypeDefinition(ref int) {
	u.unsetCurrentEnum()
}

func (u *uniqueEnumValueNamesVisitor) EnterEnumTypeExtension(ref int) {
	enumName := u.definition.EnumTypeExtensionNameBytes(ref)
	u.setCurrentEnum(enumName)
}

func (u *uniqueEnumValueNamesVisitor) LeaveEnumTypeExtension(ref int) {
	u.unsetCurrentEnum()
}

func (u *uniqueEnumValueNamesVisitor) setCurrentEnum(enumName ast.ByteSlice) {
	u.currentEnumName = enumName
	u.currentEnumHash = xxhash.Sum64(enumName)
}

func (u *uniqueEnumValueNamesVisitor) unsetCurrentEnum() {
	u.currentEnumName = u.currentEnumName[:0]
	u.currentEnumHash = 0
}

func (u *uniqueEnumValueNamesVisitor) checkEnumValueName(enumValueName ast.ByteSlice) {
	if len(u.currentEnumName) == 0 || u.currentEnumHash == 0 {
		return
	}

	enumValueNameHash := xxhash.Sum64(enumValueName)
	enumValueNames, ok := u.usedEnumValues[u.currentEnumHash]
	if !ok {
		enumValueNames = make(hashedEnumValueNames)
	}

	if enumValueNames[enumValueNameHash] {
		u.Report.AddExternalError(operationreport.ErrEnumValueNameMustBeUnique(u.currentEnumName, enumValueName))
		return
	}

	enumValueNames[enumValueNameHash] = true
	u.usedEnumValues[u.currentEnumHash] = enumValueNames
}

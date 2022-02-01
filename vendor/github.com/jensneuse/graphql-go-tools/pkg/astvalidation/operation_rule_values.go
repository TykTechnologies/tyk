package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astimport"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// Values validates if values are used properly
func Values() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := valuesVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterArgumentVisitor(&visitor)
	}
}

type valuesVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	importer              astimport.Importer
}

func (v *valuesVisitor) EnterDocument(operation, definition *ast.Document) {
	v.operation = operation
	v.definition = definition
}

func (v *valuesVisitor) EnterArgument(ref int) {

	definition, exists := v.ArgumentInputValueDefinition(ref)

	if !exists {
		argName := v.operation.ArgumentNameBytes(ref)
		nodeName := v.operation.NodeNameBytes(v.Ancestors[len(v.Ancestors)-1])
		v.StopWithExternalErr(operationreport.ErrArgumentNotDefinedOnNode(argName, nodeName))
		return
	}

	value := v.operation.ArgumentValue(ref)
	if value.Kind == ast.ValueKindVariable {
		variableName := v.operation.VariableValueNameBytes(value.Ref)
		variableDefinition, exists := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, variableName)
		if !exists {
			operationName := v.operation.NodeNameBytes(v.Ancestors[0])
			v.StopWithExternalErr(operationreport.ErrVariableNotDefinedOnOperation(variableName, operationName))
			return
		}
		if !v.operation.VariableDefinitions[variableDefinition].DefaultValue.IsDefined {
			return // variable has no default value, deep type check not required
		}
		value = v.operation.VariableDefinitions[variableDefinition].DefaultValue.Value
	}

	if !v.valueSatisfiesInputValueDefinitionType(value, v.definition.InputValueDefinitions[definition].Type) {

		printedValue, err := v.operation.PrintValueBytes(value, nil)
		if v.HandleInternalErr(err) {
			return
		}

		printedType, err := v.definition.PrintTypeBytes(v.definition.InputValueDefinitions[definition].Type, nil)
		if v.HandleInternalErr(err) {
			return
		}

		v.StopWithExternalErr(operationreport.ErrValueDoesntSatisfyInputValueDefinition(printedValue, printedType))
		return
	}
}

func (v *valuesVisitor) valueSatisfiesInputValueDefinitionType(value ast.Value, definitionTypeRef int) bool {

	switch v.definition.Types[definitionTypeRef].TypeKind {
	case ast.TypeKindNonNull:
		switch value.Kind {
		case ast.ValueKindNull:
			return false
		case ast.ValueKindVariable:
			variableName := v.operation.VariableValueNameBytes(value.Ref)
			variableDefinition, exists := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, variableName)
			if !exists {
				return false
			}
			variableTypeRef := v.operation.VariableDefinitions[variableDefinition].Type
			importedDefinitionType := v.importer.ImportType(definitionTypeRef, v.definition, v.operation)
			if !v.operation.TypesAreEqualDeep(importedDefinitionType, variableTypeRef) {
				return false
			}
		}
		return v.valueSatisfiesInputValueDefinitionType(value, v.definition.Types[definitionTypeRef].OfType)
	case ast.TypeKindNamed:
		typeName := v.definition.ResolveTypeNameBytes(definitionTypeRef)
		node, exists := v.definition.Index.FirstNodeByNameBytes(typeName)
		if !exists {
			return false
		}
		return v.valueSatisfiesTypeDefinitionNode(value, node)
	case ast.TypeKindList:
		return v.valueSatisfiesListType(value, v.definition.Types[definitionTypeRef].OfType)
	default:
		return false
	}
}

func (v *valuesVisitor) valueSatisfiesListType(value ast.Value, listType int) bool {

	if value.Kind == ast.ValueKindVariable {
		variableName := v.operation.VariableValueNameBytes(value.Ref)
		variableDefinition, exists := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, variableName)
		if !exists {
			return false
		}
		actualType := v.operation.VariableDefinitions[variableDefinition].Type
		expectedType := v.importer.ImportType(listType, v.definition, v.operation)
		if v.operation.Types[actualType].TypeKind == ast.TypeKindNonNull {
			actualType = v.operation.Types[actualType].OfType
		}
		if v.operation.Types[actualType].TypeKind == ast.TypeKindList {
			actualType = v.operation.Types[actualType].OfType
		}
		return v.operation.TypesAreEqualDeep(expectedType, actualType)
	}

	if value.Kind != ast.ValueKindList {
		return false
	}

	if v.definition.Types[listType].TypeKind == ast.TypeKindNonNull {
		if len(v.operation.ListValues[value.Ref].Refs) == 0 {
			return false
		}
		listType = v.definition.Types[listType].OfType
	}

	for _, i := range v.operation.ListValues[value.Ref].Refs {
		listValue := v.operation.Value(i)
		if !v.valueSatisfiesInputValueDefinitionType(listValue, listType) {
			return false
		}
	}

	return true
}

func (v *valuesVisitor) valueSatisfiesTypeDefinitionNode(value ast.Value, node ast.Node) bool {
	switch node.Kind {
	case ast.NodeKindEnumTypeDefinition:
		return v.valueSatisfiesEnum(value, node)
	case ast.NodeKindScalarTypeDefinition:
		return v.valueSatisfiesScalar(value, node.Ref)
	case ast.NodeKindInputObjectTypeDefinition:
		return v.valueSatisfiesInputObjectTypeDefinition(value, node.Ref)
	default:
		return false
	}
}

func (v *valuesVisitor) valueSatisfiesEnum(value ast.Value, node ast.Node) bool {
	if value.Kind == ast.ValueKindVariable {
		name := v.operation.VariableValueNameBytes(value.Ref)
		if v.Ancestors[0].Kind != ast.NodeKindOperationDefinition {
			return false
		}
		definition, ok := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, name)
		if !ok {
			return false
		}
		variableType := v.operation.VariableDefinitions[definition].Type
		actualTypeName := v.operation.ResolveTypeNameBytes(variableType)
		expectedTypeName := node.NameBytes(v.definition)
		return bytes.Equal(actualTypeName, expectedTypeName)
	}
	if value.Kind != ast.ValueKindEnum {
		return false
	}
	enumValue := v.operation.EnumValueNameBytes(value.Ref)
	return v.definition.EnumTypeDefinitionContainsEnumValue(node.Ref, enumValue)
}

func (v *valuesVisitor) valueSatisfiesInputObjectTypeDefinition(value ast.Value, inputObjectTypeDefinition int) bool {

	if value.Kind == ast.ValueKindVariable {
		name := v.operation.VariableValueNameBytes(value.Ref)
		if v.Ancestors[0].Kind != ast.NodeKindOperationDefinition {
			return false
		}
		definition, ok := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, name)
		if !ok {
			return false
		}
		variableType := v.operation.VariableDefinitions[definition].Type
		actualTypeName := v.operation.ResolveTypeNameBytes(variableType)
		expectedTypeName := v.definition.InputObjectTypeDefinitionNameBytes(inputObjectTypeDefinition)
		return bytes.Equal(actualTypeName, expectedTypeName)
	}

	if value.Kind != ast.ValueKindObject {
		return false
	}

	for _, i := range v.definition.InputObjectTypeDefinitions[inputObjectTypeDefinition].InputFieldsDefinition.Refs {
		if !v.objectValueSatisfiesInputValueDefinition(value.Ref, i) {
			return false
		}
	}

	for _, i := range v.operation.ObjectValues[value.Ref].Refs {
		if !v.objectFieldDefined(i, inputObjectTypeDefinition) {
			objectFieldName := string(v.operation.ObjectFieldNameBytes(i))
			def := string(v.definition.Input.ByteSlice(v.definition.InputObjectTypeDefinitions[inputObjectTypeDefinition].Name))
			_, _ = objectFieldName, def
			return false
		}
	}

	return !v.objectValueHasDuplicateFields(value.Ref)
}

func (v *valuesVisitor) objectValueHasDuplicateFields(objectValue int) bool {
	for i, j := range v.operation.ObjectValues[objectValue].Refs {
		for k, l := range v.operation.ObjectValues[objectValue].Refs {
			if i == k || i > k {
				continue
			}
			if bytes.Equal(v.operation.ObjectFieldNameBytes(j), v.operation.ObjectFieldNameBytes(l)) {
				return true
			}
		}
	}
	return false
}

func (v *valuesVisitor) objectFieldDefined(objectField, inputObjectTypeDefinition int) bool {
	name := v.operation.ObjectFieldNameBytes(objectField)
	for _, i := range v.definition.InputObjectTypeDefinitions[inputObjectTypeDefinition].InputFieldsDefinition.Refs {
		if bytes.Equal(name, v.definition.InputValueDefinitionNameBytes(i)) {
			return true
		}
	}
	return false
}

func (v *valuesVisitor) objectValueSatisfiesInputValueDefinition(objectValue, inputValueDefinition int) bool {

	name := v.definition.InputValueDefinitionNameBytes(inputValueDefinition)
	definitionType := v.definition.InputValueDefinitionType(inputValueDefinition)

	for _, i := range v.operation.ObjectValues[objectValue].Refs {
		if bytes.Equal(name, v.operation.ObjectFieldNameBytes(i)) {
			value := v.operation.ObjectFieldValue(i)
			return v.valueSatisfiesInputValueDefinitionType(value, definitionType)
		}
	}

	// argument is not present on object value, if arg is optional it's still ok, otherwise not satisfied
	return v.definition.InputValueDefinitionArgumentIsOptional(inputValueDefinition)
}

func (v *valuesVisitor) valueSatisfiesScalar(value ast.Value, scalar int) bool {
	scalarName := v.definition.ScalarTypeDefinitionNameString(scalar)
	if value.Kind == ast.ValueKindVariable {
		variableName := v.operation.VariableValueNameBytes(value.Ref)
		variableDefinition, exists := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, variableName)
		if !exists {
			return false
		}
		variableTypeRef := v.operation.VariableDefinitions[variableDefinition].Type
		typeName := v.operation.ResolveTypeNameString(variableTypeRef)
		return scalarName == typeName
	}
	switch scalarName {
	case "Boolean":
		return value.Kind == ast.ValueKindBoolean
	case "Int":
		return value.Kind == ast.ValueKindInteger
	case "Float":
		return value.Kind == ast.ValueKindFloat || value.Kind == ast.ValueKindInteger
	default:
		return value.Kind == ast.ValueKindString
	}
}

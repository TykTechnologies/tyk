package astvalidation

import (
	"bytes"
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// ValidArguments validates if arguments are valid
func ValidArguments() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := validArgumentsVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterArgumentVisitor(&visitor)
	}
}

type validArgumentsVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (v *validArgumentsVisitor) EnterDocument(operation, definition *ast.Document) {
	v.operation = operation
	v.definition = definition
}

func (v *validArgumentsVisitor) EnterArgument(ref int) {
	definition, exists := v.ArgumentInputValueDefinition(ref)

	if !exists {
		argumentName := v.operation.ArgumentNameBytes(ref)
		ancestorName := v.AncestorNameBytes()
		v.StopWithExternalErr(operationreport.ErrArgumentNotDefinedOnNode(argumentName, ancestorName))
		return
	}

	value := v.operation.ArgumentValue(ref)
	v.validateIfValueSatisfiesInputFieldDefinition(value, definition)
}

func (v *validArgumentsVisitor) validateIfValueSatisfiesInputFieldDefinition(value ast.Value, inputValueDefinition int) {
	var satisfied bool

	switch value.Kind {
	case ast.ValueKindVariable:
		satisfied = v.variableValueSatisfiesInputValueDefinition(value.Ref, inputValueDefinition)
	case ast.ValueKindEnum:
		satisfied = v.enumValueSatisfiesInputValueDefinition(value.Ref, inputValueDefinition)
	case ast.ValueKindNull:
		satisfied = v.nullValueSatisfiesInputValueDefinition(inputValueDefinition)
	case ast.ValueKindBoolean:
		satisfied = v.booleanValueSatisfiesInputValueDefinition(inputValueDefinition)
	case ast.ValueKindInteger:
		satisfied = v.intValueSatisfiesInputValueDefinition(value, inputValueDefinition)
	case ast.ValueKindString:
		satisfied = v.stringValueSatisfiesInputValueDefinition(value, inputValueDefinition)
	case ast.ValueKindFloat:
		satisfied = v.floatValueSatisfiesInputValueDefinition(value, inputValueDefinition)
	case ast.ValueKindObject, ast.ValueKindList:
		// object- and list values are covered by Values() / valuesVisitor
		return
	default:
		v.StopWithInternalErr(fmt.Errorf("validateIfValueSatisfiesInputFieldDefinition: not implemented for value.Kind: %s", value.Kind))
		return
	}

	if satisfied {
		return
	}

	printedValue, err := v.operation.PrintValueBytes(value, nil)
	if v.HandleInternalErr(err) {
		return
	}

	typeRef := v.definition.InputValueDefinitionType(inputValueDefinition)

	printedType, err := v.definition.PrintTypeBytes(typeRef, nil)
	if v.HandleInternalErr(err) {
		return
	}

	v.StopWithExternalErr(operationreport.ErrValueDoesntSatisfyInputValueDefinition(printedValue, printedType))
}

func (v *validArgumentsVisitor) floatValueSatisfiesInputValueDefinition(value ast.Value, inputValueDefinition int) bool {
	inputType := v.definition.Types[v.definition.InputValueDefinitionType(inputValueDefinition)]
	if inputType.TypeKind == ast.TypeKindNonNull {
		inputType = v.definition.Types[inputType.OfType]
	}
	if inputType.TypeKind != ast.TypeKindNamed {
		return false
	}
	if !bytes.Equal(v.definition.Input.ByteSlice(inputType.Name), literal.FLOAT) {
		return false
	}
	return true
}

func (v *validArgumentsVisitor) stringValueSatisfiesInputValueDefinition(value ast.Value, inputValueDefinition int) bool {
	inputType := v.definition.Types[v.definition.InputValueDefinitionType(inputValueDefinition)]
	if inputType.TypeKind == ast.TypeKindNonNull {
		inputType = v.definition.Types[inputType.OfType]
	}
	if inputType.TypeKind != ast.TypeKindNamed {
		return false
	}

	inputTypeName := v.definition.Input.ByteSlice(inputType.Name)
	if !bytes.Equal(inputTypeName, literal.STRING) && !bytes.Equal(inputTypeName, literal.ID) {
		return false
	}
	return true
}

func (v *validArgumentsVisitor) intValueSatisfiesInputValueDefinition(value ast.Value, inputValueDefinition int) bool {
	inputType := v.definition.Types[v.definition.InputValueDefinitionType(inputValueDefinition)]
	if inputType.TypeKind == ast.TypeKindNonNull {
		inputType = v.definition.Types[inputType.OfType]
	}
	if inputType.TypeKind != ast.TypeKindNamed {
		return false
	}
	if !bytes.Equal(v.definition.Input.ByteSlice(inputType.Name), literal.INT) {
		return false
	}
	return true
}

func (v *validArgumentsVisitor) booleanValueSatisfiesInputValueDefinition(inputValueDefinition int) bool {
	inputType := v.definition.Types[v.definition.InputValueDefinitionType(inputValueDefinition)]
	if inputType.TypeKind == ast.TypeKindNonNull {
		inputType = v.definition.Types[inputType.OfType]
	}
	if inputType.TypeKind != ast.TypeKindNamed {
		return false
	}
	if !bytes.Equal(v.definition.Input.ByteSlice(inputType.Name), literal.BOOLEAN) {
		return false
	}
	return true
}

func (v *validArgumentsVisitor) nullValueSatisfiesInputValueDefinition(inputValueDefinition int) bool {
	inputType := v.definition.Types[v.definition.InputValueDefinitionType(inputValueDefinition)]
	return inputType.TypeKind != ast.TypeKindNonNull
}

func (v *validArgumentsVisitor) enumValueSatisfiesInputValueDefinition(enumValue, inputValueDefinition int) bool {
	definitionTypeName := v.definition.ResolveTypeNameBytes(v.definition.InputValueDefinitions[inputValueDefinition].Type)
	node, exists := v.definition.Index.FirstNodeByNameBytes(definitionTypeName)
	if !exists {
		return false
	}

	if node.Kind != ast.NodeKindEnumTypeDefinition {
		return false
	}

	enumValueName := v.operation.Input.ByteSlice(v.operation.EnumValueName(enumValue))
	return v.definition.EnumTypeDefinitionContainsEnumValue(node.Ref, enumValueName)
}

func (v *validArgumentsVisitor) variableValueSatisfiesInputValueDefinition(variableValue, inputValueDefinition int) bool {
	variableName := v.operation.VariableValueNameBytes(variableValue)
	variableDefinition, exists := v.operation.VariableDefinitionByNameAndOperation(v.Ancestors[0].Ref, variableName)
	if !exists {
		return false
	}

	operationType := v.operation.VariableDefinitions[variableDefinition].Type
	definitionType := v.definition.InputValueDefinitions[inputValueDefinition].Type
	hasDefaultValue := v.operation.VariableDefinitions[variableDefinition].DefaultValue.IsDefined ||
		v.definition.InputValueDefinitions[inputValueDefinition].DefaultValue.IsDefined

	return v.operationTypeSatisfiesDefinitionType(operationType, definitionType, hasDefaultValue)
}

func (v *validArgumentsVisitor) operationTypeSatisfiesDefinitionType(operationType int, definitionType int, hasDefaultValue bool) bool {
	opKind := v.operation.Types[operationType].TypeKind
	defKind := v.definition.Types[definitionType].TypeKind

	// A nullable op type is compatible with a non-null def type if the def has
	// a default value. Strip the def non-null and continue comparing. This
	// logic is only valid before any unnesting of types occurs, which is why
	// it's outside the for loop below.
	//
	// Example:
	// Op:  someField(arg: Boolean): String
	// Def: someField(arg: Boolean! = false): String  #  Boolean! -> Boolean
	if opKind != ast.TypeKindNonNull && defKind == ast.TypeKindNonNull && hasDefaultValue {
		definitionType = v.definition.Types[definitionType].OfType
	}

	// Unnest the op and def arg types until a named type is reached,
	// then compare.
	for {
		if operationType == -1 || definitionType == -1 {
			return false
		}
		opKind = v.operation.Types[operationType].TypeKind
		defKind = v.definition.Types[definitionType].TypeKind

		// If the op arg type is stricter than the def arg type, that's okay.
		// Strip the op non-null and continue comparing.
		//
		// Example:
		// Op:  someField(arg: Boolean!): String  # Boolean! -> Boolean
		// Def: someField(arg: Boolean): String
		if opKind == ast.TypeKindNonNull && defKind != ast.TypeKindNonNull {
			operationType = v.operation.Types[operationType].OfType
			continue
		}

		if opKind != defKind {
			return false
		}
		if opKind == ast.TypeKindNamed {
			// defKind is also a named type because at this point both kinds
			// are the same! Compare the names.
			return bytes.Equal(v.operation.Input.ByteSlice(v.operation.Types[operationType].Name),
				v.definition.Input.ByteSlice(v.definition.Types[definitionType].Name))
		}
		// Both types are non-null or list. Unnest and continue comparing.
		operationType = v.operation.Types[operationType].OfType
		definitionType = v.definition.Types[definitionType].OfType
	}
}

package astnormalization

import (
	"bytes"

	"github.com/buger/jsonparser"
	"github.com/tidwall/sjson"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astimport"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func extractVariablesDefaultValue(walker *astvisitor.Walker) *variablesDefaultValueExtractionVisitor {
	visitor := &variablesDefaultValueExtractionVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(visitor)
	walker.RegisterEnterOperationVisitor(visitor)
	walker.RegisterEnterVariableDefinitionVisitor(visitor)
	walker.RegisterEnterFieldVisitor(visitor)
	return visitor
}

type variablesDefaultValueExtractionVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	importer              astimport.Importer
	operationName         []byte
	operationRef          int
	skip                  bool
}

func (v *variablesDefaultValueExtractionVisitor) EnterField(ref int) {
	if v.skip {
		return
	}

	// find field definition from document
	fieldName := v.operation.FieldNameBytes(ref)
	fieldDefRef, ok := v.definition.NodeFieldDefinitionByName(v.EnclosingTypeDefinition, fieldName)
	if !ok {
		return
	}

	// skip when field has no args in the document
	if !v.definition.FieldDefinitions[fieldDefRef].HasArgumentsDefinitions {
		return
	}

	for _, argRef := range v.definition.FieldDefinitions[fieldDefRef].ArgumentsDefinition.Refs {
		_, exists := v.operation.FieldArgument(ref, v.definition.InputValueDefinitionNameBytes(argRef))
		if !exists {
			v.processDefaultFieldArguments(ref, argRef)
		}
	}
}

func (v *variablesDefaultValueExtractionVisitor) EnterVariableDefinition(ref int) {
	if v.skip {
		return
	}

	// skip when we have no default value for variable
	if !v.operation.VariableDefinitionHasDefaultValue(ref) {
		return
	}

	variableName := v.operation.VariableDefinitionNameString(ref)

	// remove variable DefaultValue from operation
	v.operation.VariableDefinitions[ref].DefaultValue.IsDefined = false

	// skip when variable was provided
	_, _, _, err := jsonparser.Get(v.operation.Input.Variables, variableName)
	if err == nil {
		return
	}

	valueBytes, err := v.operation.ValueToJSON(v.operation.VariableDefinitionDefaultValue(ref))
	if err != nil {
		return
	}

	v.operation.Input.Variables, err = sjson.SetRawBytes(v.operation.Input.Variables, variableName, valueBytes)
	if err != nil {
		v.StopWithInternalErr(err)
		return
	}
}

func (v *variablesDefaultValueExtractionVisitor) EnterOperationDefinition(ref int) {
	if len(v.operationName) == 0 {
		v.skip = false
		return
	}
	operationName := v.operation.OperationDefinitionNameBytes(ref)
	v.operationRef = ref
	v.skip = !bytes.Equal(operationName, v.operationName)
}

func (v *variablesDefaultValueExtractionVisitor) processDefaultFieldArguments(operationFieldRef, definitionInputValueDefRef int) {
	if !v.definition.InputValueDefinitionHasDefaultValue(definitionInputValueDefRef) {
		return
	}

	variableNameBytes := v.operation.GenerateUnusedVariableDefinitionName(v.Ancestors[0].Ref)
	valueBytes, err := v.definition.ValueToJSON(v.definition.InputValueDefinitionDefaultValue(definitionInputValueDefRef))
	if err != nil {
		return
	}
	v.operation.Input.Variables, err = sjson.SetRawBytes(v.operation.Input.Variables, unsafebytes.BytesToString(variableNameBytes), valueBytes)
	if err != nil {
		v.StopWithInternalErr(err)
		return
	}

	variableValueRef, argRef := v.operation.ImportVariableValueArgument(v.definition.InputValueDefinitionNameBytes(definitionInputValueDefRef), variableNameBytes)
	defType := v.definition.InputValueDefinitions[definitionInputValueDefRef].Type
	importedDefType := v.importer.ImportType(defType, v.definition, v.operation)

	v.operation.AddArgumentToField(operationFieldRef, argRef)
	v.operation.AddVariableDefinitionToOperationDefinition(v.operationRef, variableValueRef, importedDefType)
}

func (v *variablesDefaultValueExtractionVisitor) EnterDocument(operation, definition *ast.Document) {
	v.operation, v.definition = operation, definition
}

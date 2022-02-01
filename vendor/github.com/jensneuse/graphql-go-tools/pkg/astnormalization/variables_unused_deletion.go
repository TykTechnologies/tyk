package astnormalization

import (
	"bytes"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func deleteUnusedVariables(walker *astvisitor.Walker) *deleteUnusedVariablesVisitor {
	visitor := &deleteUnusedVariablesVisitor{
		Walker: walker,
	}
	visitor.Walker.RegisterEnterDocumentVisitor(visitor)
	visitor.Walker.RegisterOperationDefinitionVisitor(visitor)
	visitor.Walker.RegisterEnterVariableDefinitionVisitor(visitor)
	visitor.Walker.RegisterEnterArgumentVisitor(visitor)
	return visitor
}

type deleteUnusedVariablesVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	definedVariables      []int
	operationName         []byte
	skip                  bool
}

func (d *deleteUnusedVariablesVisitor) LeaveOperationDefinition(ref int) {
	for _, variable := range d.definedVariables {
		variableName := d.operation.VariableDefinitionNameString(variable)
		for i, variableDefinitionRef := range d.operation.OperationDefinitions[ref].VariableDefinitions.Refs {
			if variable == variableDefinitionRef {
				d.operation.OperationDefinitions[ref].VariableDefinitions.Refs = append(d.operation.OperationDefinitions[ref].VariableDefinitions.Refs[:i], d.operation.OperationDefinitions[ref].VariableDefinitions.Refs[i+1:]...)
				d.operation.Input.Variables = jsonparser.Delete(d.operation.Input.Variables, variableName)
				d.operation.OperationDefinitions[ref].HasVariableDefinitions = len(d.operation.OperationDefinitions[ref].VariableDefinitions.Refs) != 0
			}
		}

	}
	d.skip = true
}

func (d *deleteUnusedVariablesVisitor) removeDefinedVariableWithName(name []byte) {
	for i, variable := range d.definedVariables {
		definedVariableNameBytes := d.operation.VariableDefinitionNameBytes(variable)
		if bytes.Equal(name, definedVariableNameBytes) {
			d.definedVariables = append(d.definedVariables[:i], d.definedVariables[i+1:]...)
			d.removeDefinedVariableWithName(name)
			return
		}
	}
}

func (d *deleteUnusedVariablesVisitor) traverseValue(value ast.Value) {
	switch value.Kind {
	case ast.ValueKindVariable:
		d.removeDefinedVariableWithName(d.operation.VariableValueNameBytes(value.Ref))
	case ast.ValueKindList:
		for _, ref := range d.operation.ListValues[value.Ref].Refs {
			d.traverseValue(d.operation.Value(ref))
		}
	case ast.ValueKindObject:
		for _, ref := range d.operation.ObjectValues[value.Ref].Refs {
			d.traverseValue(d.operation.ObjectField(ref).Value)
		}
	}
}

func (d *deleteUnusedVariablesVisitor) EnterArgument(ref int) {
	if d.skip {
		return
	}
	d.traverseValue(d.operation.Arguments[ref].Value)
}

func (d *deleteUnusedVariablesVisitor) EnterVariableDefinition(ref int) {
	if d.skip {
		return
	}
	d.definedVariables = append(d.definedVariables, ref)
}

func (d *deleteUnusedVariablesVisitor) EnterOperationDefinition(ref int) {
	d.definedVariables = d.definedVariables[:0]
	d.skip = false
}

func (d *deleteUnusedVariablesVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation, d.definition = operation, definition
}

package astvalidation

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// AllVariablesUsed validates if all defined variables are used
func AllVariablesUsed() Rule {
	return func(walker *astvisitor.Walker) {
		visitor := allVariablesUsedVisitor{
			Walker: walker,
		}
		walker.RegisterEnterDocumentVisitor(&visitor)
		walker.RegisterEnterOperationVisitor(&visitor)
		walker.RegisterLeaveOperationVisitor(&visitor)
		walker.RegisterEnterArgumentVisitor(&visitor)
	}
}

type allVariablesUsedVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	variableDefinitions   []int
}

func (a *allVariablesUsedVisitor) EnterDocument(operation, definition *ast.Document) {
	a.operation = operation
	a.definition = definition
	a.variableDefinitions = a.variableDefinitions[:0]
}

func (a *allVariablesUsedVisitor) EnterOperationDefinition(ref int) {
	a.variableDefinitions = append(a.variableDefinitions, a.operation.OperationDefinitions[ref].VariableDefinitions.Refs...)
}

func (a *allVariablesUsedVisitor) LeaveOperationDefinition(ref int) {
	if len(a.variableDefinitions) != 0 {
		operationName := a.operation.Input.ByteSlice(a.operation.OperationDefinitions[ref].Name)
		for _, i := range a.variableDefinitions {
			variableName := a.operation.VariableDefinitionNameBytes(i)
			a.Report.AddExternalError(operationreport.ErrVariableDefinedButNeverUsed(variableName, operationName))
		}
		a.Stop()
	}
}

func (a *allVariablesUsedVisitor) EnterArgument(ref int) {

	if len(a.variableDefinitions) == 0 {
		return // nothing to check, skip
	}

	a.verifyValue(a.operation.Arguments[ref].Value)
}

func (a *allVariablesUsedVisitor) verifyValue(value ast.Value) {
	switch value.Kind {
	case ast.ValueKindVariable: // don't skip
	case ast.ValueKindObject:
		for _, i := range a.operation.ObjectValues[value.Ref].Refs {
			a.verifyValue(a.operation.ObjectFields[i].Value)
		}
		return
	case ast.ValueKindList:
		for _, i := range a.operation.ListValues[value.Ref].Refs {
			a.verifyValue(a.operation.Values[i])
		}
	default:
		return // skip all others
	}

	variableName := a.operation.VariableValueNameBytes(value.Ref)
	for i, j := range a.variableDefinitions {
		if bytes.Equal(variableName, a.operation.VariableDefinitionNameBytes(j)) {
			a.variableDefinitions = append(a.variableDefinitions[:i], a.variableDefinitions[i+1:]...)
			return
		}
	}
}

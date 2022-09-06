package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type VariableDefinitionList struct {
	LPAREN position.Position // (
	Refs   []int             // VariableDefinition
	RPAREN position.Position // )
}

// VariableDefinition
// example:
// $devicePicSize: Int = 100 @small
type VariableDefinition struct {
	VariableValue Value             // $ Name
	Colon         position.Position // :
	Type          int               // e.g. String
	DefaultValue  DefaultValue      // optional, e.g. = "Default"
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

func (d *Document) VariableDefinitionNameBytes(ref int) ByteSlice {
	return d.VariableValueNameBytes(d.VariableDefinitions[ref].VariableValue.Ref)
}

func (d *Document) VariableDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.VariableValueNameBytes(d.VariableDefinitions[ref].VariableValue.Ref))
}

func (d *Document) VariableDefinitionByNameAndOperation(operationDefinition int, name ByteSlice) (definition int, exists bool) {
	if !d.OperationDefinitions[operationDefinition].HasVariableDefinitions {
		return -1, false
	}
	for _, i := range d.OperationDefinitions[operationDefinition].VariableDefinitions.Refs {
		definitionName := d.VariableValueNameBytes(d.VariableDefinitions[i].VariableValue.Ref)
		if bytes.Equal(name, definitionName) {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) VariableDefinitionsBefore(variableDefinition int) bool {
	for i := range d.OperationDefinitions {
		for j, k := range d.OperationDefinitions[i].VariableDefinitions.Refs {
			if k == variableDefinition {
				return j != 0
			}
		}
	}
	return false
}

func (d *Document) VariableDefinitionsAfter(variableDefinition int) bool {
	for i := range d.OperationDefinitions {
		for j, k := range d.OperationDefinitions[i].VariableDefinitions.Refs {
			if k == variableDefinition {
				return j != len(d.OperationDefinitions[i].VariableDefinitions.Refs)-1
			}
		}
	}
	return false
}

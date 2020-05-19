package ast

import (
	"bytes"

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

func (d *Document) VariableDefinitionByName(name ByteSlice) (definition int, exists bool) {
	for i := range d.VariableDefinitions {
		definitionName := d.VariableValueNameBytes(d.VariableDefinitions[i].VariableValue.Ref)
		if bytes.Equal(name, definitionName) {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) VariableDefinitionsBefore(variableDefinition int) bool {
	return variableDefinition != 0
}

func (d *Document) VariableDefinitionsAfter(variableDefinition int) bool {
	return len(d.VariableDefinitions) != 1 && variableDefinition != len(d.VariableDefinitions)-1
}

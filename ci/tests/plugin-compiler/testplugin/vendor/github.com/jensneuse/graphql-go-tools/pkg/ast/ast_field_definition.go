package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type FieldDefinitionList struct {
	LBRACE position.Position // {
	Refs   []int             // FieldDefinition
	RBRACE position.Position // }
}

type FieldDefinition struct {
	Description             Description        // optional e.g. "FieldDefinition is ..."
	Name                    ByteSliceReference // e.g. foo
	HasArgumentsDefinitions bool
	ArgumentsDefinition     InputValueDefinitionList // optional
	Colon                   position.Position        // :
	Type                    int                      // e.g. String
	HasDirectives           bool
	Directives              DirectiveList // e.g. @foo
}

func (d *Document) FieldDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FieldDefinitions[ref].Name)
}

func (d *Document) FieldDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.FieldDefinitionNameBytes(ref))
}

func (d *Document) FieldDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.FieldDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.FieldDefinitions[ref].Description.Content)
}

func (d *Document) FieldDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.FieldDefinitionDescriptionBytes(ref))
}

func (d *Document) FieldDefinitionIsFirst(field int, ancestor Node) bool {
	definitions := d.NodeFieldDefinitions(ancestor)
	return len(definitions) != 0 && definitions[0] == field
}

func (d *Document) FieldDefinitionIsLast(field int, ancestor Node) bool {
	definitions := d.NodeFieldDefinitions(ancestor)
	return len(definitions) != 0 && definitions[len(definitions)-1] == field
}

func (d *Document) FieldDefinitionHasDirectives(ref int) bool {
	return d.FieldDefinitions[ref].HasDirectives
}

func (d *Document) FieldDefinitionDirectives(fieldDefinition int) (refs []int) {
	return d.FieldDefinitions[fieldDefinition].Directives.Refs
}

func (d *Document) FieldDefinitionDirectiveByName(fieldDefinition int, directiveName ByteSlice) (ref int, exists bool) {
	for _, i := range d.FieldDefinitions[fieldDefinition].Directives.Refs {
		if bytes.Equal(directiveName, d.DirectiveNameBytes(i)) {
			return i, true
		}
	}
	return
}

func (d *Document) FieldDefinitionHasNamedDirective(fieldDefinition int, directiveName string) bool {
	_, exists := d.FieldDefinitionDirectiveByName(fieldDefinition, unsafebytes.StringToBytes(directiveName))
	return exists
}

func (d *Document) FieldDefinitionResolverTypeName(enclosingType Node) ByteSlice {
	switch enclosingType.Kind {
	case NodeKindObjectTypeDefinition:
		name := d.ObjectTypeDefinitionNameBytes(enclosingType.Ref)
		switch {
		case bytes.Equal(name, d.Index.QueryTypeName):
			return literal.QUERY
		case bytes.Equal(name, d.Index.MutationTypeName):
			return literal.MUTATION
		case bytes.Equal(name, d.Index.SubscriptionTypeName):
			return literal.SUBSCRIPTION
		}
	}
	return d.NodeNameBytes(enclosingType)
}

func (d *Document) AddFieldDefinition(fieldDefinition FieldDefinition) (ref int) {
	d.FieldDefinitions = append(d.FieldDefinitions, fieldDefinition)
	return len(d.FieldDefinitions) - 1
}

func (d *Document) ImportFieldDefinition(name, description string, typeRef int, argsRefs []int, directiveRefs []int) (ref int) {
	fieldDef := FieldDefinition{
		Name:        d.Input.AppendInputString(name),
		Type:        typeRef,
		Description: d.ImportDescription(description),
		ArgumentsDefinition: InputValueDefinitionList{
			Refs: argsRefs,
		},
		HasArgumentsDefinitions: len(argsRefs) > 0,
		Directives: DirectiveList{
			Refs: directiveRefs,
		},
		HasDirectives: len(directiveRefs) > 0,
	}

	return d.AddFieldDefinition(fieldDef)
}

func (d *Document) FieldDefinitionsContainField(definitions []int, field ByteSlice) bool {
	for _, i := range definitions {
		if bytes.Equal(field, d.FieldDefinitionNameBytes(i)) {
			return true
		}
	}
	return false
}

func (d *Document) FieldDefinitionHasArgumentsDefinitions(ref int) bool {
	return d.FieldDefinitions[ref].HasArgumentsDefinitions
}

func (d *Document) FieldDefinitionArgumentsDefinitions(ref int) []int {
	return d.FieldDefinitions[ref].ArgumentsDefinition.Refs
}

func (d *Document) FieldDefinitionType(ref int) int {
	return d.FieldDefinitions[ref].Type
}

func (d *Document) FieldDefinitionTypeNode(ref int) Node {
	typeName := d.ResolveTypeNameBytes(d.FieldDefinitions[ref].Type)
	node, _ := d.Index.FirstNodeByNameBytes(typeName)
	return node
}

func (d *Document) RemoveFieldDefinitionsFromObjectTypeDefinition(fieldDefinitionRefs []int, objectTypeDefinitionRef int) {
	for _, fieldRef := range fieldDefinitionRefs {
		if i, ok := indexOf(d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs, fieldRef); ok {
			deleteRef(&d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs, i)
		}
	}
	d.ObjectTypeDefinitions[objectTypeDefinitionRef].HasFieldDefinitions = len(d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs) > 0
}

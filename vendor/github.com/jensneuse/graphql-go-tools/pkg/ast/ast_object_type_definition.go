package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type TypeList struct {
	Refs []int // Type
}

type ObjectTypeDefinition struct {
	Description          Description        // optional, e.g. "type Foo is ..."
	TypeLiteral          position.Position  // type
	Name                 ByteSliceReference // e.g. Foo
	ImplementsInterfaces TypeList           // e.g implements Bar & Baz
	HasDirectives        bool
	Directives           DirectiveList // e.g. @foo
	HasFieldDefinitions  bool
	FieldsDefinition     FieldDefinitionList // { foo:Bar bar(baz:String) }
}

func (d *Document) ObjectTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ObjectTypeDefinitions[ref].Name)
}

func (d *Document) ObjectTypeDefinitionNameRef(ref int) ByteSliceReference {
	return d.ObjectTypeDefinitions[ref].Name
}

func (d *Document) ObjectTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ObjectTypeDefinitions[ref].Name))
}

func (d *Document) ObjectTypeDescriptionNameBytes(ref int) ByteSlice {
	if !d.ObjectTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.ObjectTypeDefinitions[ref].Description.Content)
}

func (d *Document) ObjectTypeDescriptionNameString(ref int) string {
	return unsafebytes.BytesToString(d.ObjectTypeDescriptionNameBytes(ref))
}

func (d *Document) ObjectTypeDefinitionHasField(ref int, fieldName []byte) bool {
	for _, fieldDefinitionRef := range d.ObjectTypeDefinitions[ref].FieldsDefinition.Refs {
		currentFieldName := d.FieldDefinitionNameBytes(fieldDefinitionRef)
		if currentFieldName.Equals(fieldName) {
			return true
		}
	}
	return false
}

func (d *Document) ObjectTypeDefinitionImplementsInterface(definitionRef int, interfaceName ByteSlice) bool {
	for _, iRef := range d.ObjectTypeDefinitions[definitionRef].ImplementsInterfaces.Refs {
		implements := d.ResolveTypeNameBytes(iRef)
		if bytes.Equal(interfaceName, implements) {
			return true
		}
	}
	return false
}

func (d *Document) AddObjectTypeDefinition(definition ObjectTypeDefinition) (ref int) {
	d.ObjectTypeDefinitions = append(d.ObjectTypeDefinitions, definition)
	return len(d.ObjectTypeDefinitions) - 1
}

func (d *Document) ImportObjectTypeDefinition(name, description string, fieldRefs []int, iRefs []int) (ref int) {
	definition := ObjectTypeDefinition{
		Name:        d.Input.AppendInputString(name),
		Description: d.ImportDescription(description),
		FieldsDefinition: FieldDefinitionList{
			Refs: fieldRefs,
		},
		HasFieldDefinitions: len(fieldRefs) > 0,
		ImplementsInterfaces: TypeList{
			Refs: iRefs,
		},
	}

	ref = d.AddObjectTypeDefinition(definition)
	d.ImportRootNode(ref, NodeKindObjectTypeDefinition)

	return
}

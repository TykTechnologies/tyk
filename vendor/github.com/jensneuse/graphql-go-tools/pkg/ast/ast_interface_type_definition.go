package ast

import (
	"sort"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// InterfaceTypeDefinition
// example:
// interface NamedEntity {
// 	name: String
// }
type InterfaceTypeDefinition struct {
	Description         Description        // optional, describes the interface
	InterfaceLiteral    position.Position  // interface
	Name                ByteSliceReference // e.g. NamedEntity
	HasDirectives       bool
	Directives          DirectiveList // optional, e.g. @foo
	HasFieldDefinitions bool
	FieldsDefinition    FieldDefinitionList // optional, e.g. { name: String }
}

func (d *Document) InterfaceTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InterfaceTypeDefinitions[ref].Name)
}

func (d *Document) InterfaceTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InterfaceTypeDefinitions[ref].Name))
}

func (d *Document) InterfaceTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.InterfaceTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InterfaceTypeDefinitions[ref].Description.Content)
}

func (d *Document) InterfaceTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InterfaceTypeDefinitionDescriptionBytes(ref))
}

// InterfaceTypeDefinitionImplementedByRootNodes will return all RootNodes that implement the given interface type (by ref)
func (d *Document) InterfaceTypeDefinitionImplementedByRootNodes(ref int) []Node {
	interfaceTypeName := d.InterfaceTypeDefinitionNameBytes(ref)
	implementingRootNodes := make(map[Node]bool)
	for i := 0; i < len(d.RootNodes); i++ {
		if d.RootNodes[i].Kind == NodeKindInterfaceTypeDefinition && d.RootNodes[i].Ref == ref {
			continue
		}

		var rootNodeInterfaceRefs []int
		switch d.RootNodes[i].Kind {
		case NodeKindObjectTypeDefinition:
			if len(d.ObjectTypeDefinitions[d.RootNodes[i].Ref].ImplementsInterfaces.Refs) == 0 {
				continue
			}
			rootNodeInterfaceRefs = d.ObjectTypeDefinitions[d.RootNodes[i].Ref].ImplementsInterfaces.Refs
		case NodeKindInterfaceTypeDefinition:
			// Not supported in this version
			continue
		default:
			continue
		}

		for j := 0; j < len(rootNodeInterfaceRefs); j++ {
			implementedInterfaceTypeName := d.TypeNameBytes(rootNodeInterfaceRefs[j])
			if !interfaceTypeName.Equals(implementedInterfaceTypeName) {
				continue
			}

			var typeName ByteSlice
			switch d.RootNodes[i].Kind {
			case NodeKindObjectTypeDefinition:
				typeName = d.ObjectTypeDefinitionNameBytes(d.RootNodes[i].Ref)
			case NodeKindInterfaceTypeDefinition:
				typeName = d.InterfaceTypeDefinitionNameBytes(d.RootNodes[i].Ref)
			}

			node, exists := d.Index.FirstNodeByNameBytes(typeName)
			if !exists {
				continue
			}

			_, isAlreadyAdded := implementingRootNodes[node]
			if isAlreadyAdded {
				continue
			}

			implementingRootNodes[node] = true
		}
	}

	var nodes []Node
	for mapNode := range implementingRootNodes {
		nodes = append(nodes, mapNode)
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Ref < nodes[j].Ref
	})

	return nodes
}

func (d *Document) AddInterfaceTypeDefinition(definition InterfaceTypeDefinition) (ref int) {
	d.InterfaceTypeDefinitions = append(d.InterfaceTypeDefinitions, definition)
	return len(d.InterfaceTypeDefinitions) - 1
}

func (d *Document) ImportInterfaceTypeDefinition(name, description string, fieldRefs []int) (ref int) {
	definition := InterfaceTypeDefinition{
		Name:        d.Input.AppendInputString(name),
		Description: d.ImportDescription(description),
		FieldsDefinition: FieldDefinitionList{
			Refs: fieldRefs,
		},
		HasFieldDefinitions: len(fieldRefs) > 0,
	}

	ref = d.AddInterfaceTypeDefinition(definition)
	d.ImportRootNode(ref, NodeKindInterfaceTypeDefinition)

	return
}

//go:generate stringer -type=OperationType,ValueKind,TypeKind,SelectionKind,NodeKind,PathKind -output ast_string.go

// Package ast defines the GraphQL AST and offers helper methods to interact with the AST, mostly to get the necessary information from the ast.
//
// The document struct is designed in a way to enable performant parsing while keeping the ast easy to use with helper methods.
package ast

import (
	"bytes"
	"fmt"
	"github.com/cespare/xxhash"
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/runes"
	"io"
	"log"
	"strconv"
	"unsafe"
)

type OperationType int
type ValueKind int
type TypeKind int
type SelectionKind int
type NodeKind int

const (
	OperationTypeUnknown OperationType = iota
	OperationTypeQuery
	OperationTypeMutation
	OperationTypeSubscription

	ValueKindUnknown ValueKind = iota
	ValueKindString
	ValueKindBoolean
	ValueKindInteger
	ValueKindFloat
	ValueKindVariable
	ValueKindNull
	ValueKindList
	ValueKindObject
	ValueKindEnum

	TypeKindUnknown TypeKind = iota
	TypeKindNamed
	TypeKindList
	TypeKindNonNull

	SelectionKindUnknown SelectionKind = iota
	SelectionKindField
	SelectionKindFragmentSpread
	SelectionKindInlineFragment

	NodeKindUnknown NodeKind = iota
	NodeKindSchemaDefinition
	NodeKindSchemaExtension
	NodeKindObjectTypeDefinition
	NodeKindObjectTypeExtension
	NodeKindInterfaceTypeDefinition
	NodeKindInterfaceTypeExtension
	NodeKindUnionTypeDefinition
	NodeKindUnionTypeExtension
	NodeKindEnumTypeDefinition
	NodeKindEnumValueDefinition
	NodeKindEnumTypeExtension
	NodeKindInputObjectTypeDefinition
	NodeKindInputValueDefinition
	NodeKindInputObjectTypeExtension
	NodeKindScalarTypeDefinition
	NodeKindScalarTypeExtension
	NodeKindDirectiveDefinition
	NodeKindOperationDefinition
	NodeKindSelectionSet
	NodeKindField
	NodeKindFieldDefinition
	NodeKindFragmentSpread
	NodeKindInlineFragment
	NodeKindFragmentDefinition
	NodeKindArgument
	NodeKindDirective
	NodeKindVariableDefinition
)

type Document struct {
	Input                        Input
	RootNodes                    []Node
	SchemaDefinitions            []SchemaDefinition
	SchemaExtensions             []SchemaExtension
	RootOperationTypeDefinitions []RootOperationTypeDefinition
	Directives                   []Directive
	Arguments                    []Argument
	ObjectTypeDefinitions        []ObjectTypeDefinition
	ObjectTypeExtensions         []ObjectTypeExtension
	FieldDefinitions             []FieldDefinition
	Types                        []Type
	InputValueDefinitions        []InputValueDefinition
	InputObjectTypeDefinitions   []InputObjectTypeDefinition
	InputObjectTypeExtensions    []InputObjectTypeExtension
	ScalarTypeDefinitions        []ScalarTypeDefinition
	ScalarTypeExtensions         []ScalarTypeExtension
	InterfaceTypeDefinitions     []InterfaceTypeDefinition
	InterfaceTypeExtensions      []InterfaceTypeExtension
	UnionTypeDefinitions         []UnionTypeDefinition
	UnionTypeExtensions          []UnionTypeExtension
	EnumTypeDefinitions          []EnumTypeDefinition
	EnumTypeExtensions           []EnumTypeExtension
	EnumValueDefinitions         []EnumValueDefinition
	DirectiveDefinitions         []DirectiveDefinition
	Values                       []Value
	ListValues                   []ListValue
	VariableValues               []VariableValue
	StringValues                 []StringValue
	IntValues                    []IntValue
	FloatValues                  []FloatValue
	EnumValues                   []EnumValue
	ObjectFields                 []ObjectField
	ObjectValues                 []ObjectValue
	Selections                   []Selection
	SelectionSets                []SelectionSet
	Fields                       []Field
	InlineFragments              []InlineFragment
	FragmentSpreads              []FragmentSpread
	OperationDefinitions         []OperationDefinition
	VariableDefinitions          []VariableDefinition
	FragmentDefinitions          []FragmentDefinition
	BooleanValues                [2]BooleanValue
	Refs                         [][8]int
	RefIndex                     int
	Index                        Index
}

func (d *Document) IndexOf(slice []int, ref int) (int, bool) {
	for i, j := range slice {
		if ref == j {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) FragmentDefinitionIsUsed(name ByteSlice) bool {
	for _, i := range d.Index.ReplacedFragmentSpreads {
		if bytes.Equal(name, d.FragmentSpreadNameBytes(i)) {
			return true
		}
	}
	return false
}

// ReplaceFragmentSpread replaces a fragment spread with a given selection set
// attention! this might lead to duplicate field problems because the same field with its unique field reference might be copied into the same selection set
// possible problems: changing directives or sub selections will affect both fields with the same id
// simple solution: run normalization deduplicate fields
// as part of the normalization flow this problem will be handled automatically
// just be careful in case you use this function outside of the normalization package
func (d *Document) ReplaceFragmentSpread(selectionSet int, spreadRef int, replaceWithSelectionSet int) {
	for i, j := range d.SelectionSets[selectionSet].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindFragmentSpread && d.Selections[j].Ref == spreadRef {
			d.SelectionSets[selectionSet].SelectionRefs = append(d.SelectionSets[selectionSet].SelectionRefs[:i], append(d.SelectionSets[replaceWithSelectionSet].SelectionRefs, d.SelectionSets[selectionSet].SelectionRefs[i+1:]...)...)
			d.Index.ReplacedFragmentSpreads = append(d.Index.ReplacedFragmentSpreads, spreadRef)
			return
		}
	}
}

// ReplaceFragmentSpreadWithInlineFragment replaces a given fragment spread with a inline fragment
// attention! the same rules apply as for 'ReplaceFragmentSpread', look above!
func (d *Document) ReplaceFragmentSpreadWithInlineFragment(selectionSet int, spreadRef int, replaceWithSelectionSet int, typeCondition TypeCondition) {
	d.InlineFragments = append(d.InlineFragments, InlineFragment{
		TypeCondition: typeCondition,
		SelectionSet:  replaceWithSelectionSet,
		HasSelections: len(d.SelectionSets[replaceWithSelectionSet].SelectionRefs) != 0,
	})
	ref := len(d.InlineFragments) - 1
	d.Selections = append(d.Selections, Selection{
		Kind: SelectionKindInlineFragment,
		Ref:  ref,
	})
	selectionRef := len(d.Selections) - 1
	for i, j := range d.SelectionSets[selectionSet].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindFragmentSpread && d.Selections[j].Ref == spreadRef {
			d.SelectionSets[selectionSet].SelectionRefs = append(d.SelectionSets[selectionSet].SelectionRefs[:i], append([]int{selectionRef}, d.SelectionSets[selectionSet].SelectionRefs[i+1:]...)...)
			d.Index.ReplacedFragmentSpreads = append(d.Index.ReplacedFragmentSpreads, spreadRef)
			return
		}
	}
}

func (d *Document) EmptySelectionSet(ref int) {
	d.SelectionSets[ref].SelectionRefs = d.SelectionSets[ref].SelectionRefs[:0]
}

func (d *Document) AppendSelectionSet(ref int, appendRef int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs, d.SelectionSets[appendRef].SelectionRefs...)
}

func (d *Document) ReplaceSelectionOnSelectionSet(ref, replace, with int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs[:replace], append(d.SelectionSets[with].SelectionRefs, d.SelectionSets[ref].SelectionRefs[replace+1:]...)...)
}

func (d *Document) RemoveFromSelectionSet(ref int, index int) {
	d.SelectionSets[ref].SelectionRefs = append(d.SelectionSets[ref].SelectionRefs[:index], d.SelectionSets[ref].SelectionRefs[index+1:]...)
}

func NewDocument() *Document {

	return &Document{
		RootNodes:                    make([]Node, 0, 48),
		RootOperationTypeDefinitions: make([]RootOperationTypeDefinition, 0, 3),
		SchemaDefinitions:            make([]SchemaDefinition, 0, 2),
		SchemaExtensions:             make([]SchemaExtension, 0, 2),
		Directives:                   make([]Directive, 0, 16),
		Arguments:                    make([]Argument, 0, 48),
		ObjectTypeDefinitions:        make([]ObjectTypeDefinition, 0, 48),
		ObjectTypeExtensions:         make([]ObjectTypeExtension, 0, 4),
		Types:                        make([]Type, 0, 48),
		FieldDefinitions:             make([]FieldDefinition, 0, 128),
		InputValueDefinitions:        make([]InputValueDefinition, 0, 128),
		InputObjectTypeDefinitions:   make([]InputObjectTypeDefinition, 0, 16),
		InputObjectTypeExtensions:    make([]InputObjectTypeExtension, 0, 4),
		ScalarTypeDefinitions:        make([]ScalarTypeDefinition, 0, 16),
		ScalarTypeExtensions:         make([]ScalarTypeExtension, 0, 4),
		InterfaceTypeDefinitions:     make([]InterfaceTypeDefinition, 0, 16),
		InterfaceTypeExtensions:      make([]InterfaceTypeExtension, 0, 4),
		UnionTypeDefinitions:         make([]UnionTypeDefinition, 0, 8),
		UnionTypeExtensions:          make([]UnionTypeExtension, 0, 4),
		EnumTypeDefinitions:          make([]EnumTypeDefinition, 0, 8),
		EnumTypeExtensions:           make([]EnumTypeExtension, 0, 4),
		EnumValueDefinitions:         make([]EnumValueDefinition, 0, 48),
		DirectiveDefinitions:         make([]DirectiveDefinition, 0, 8),
		VariableValues:               make([]VariableValue, 0, 8),
		StringValues:                 make([]StringValue, 0, 24),
		EnumValues:                   make([]EnumValue, 0, 24),
		IntValues:                    make([]IntValue, 0, 128),
		FloatValues:                  make([]FloatValue, 0, 128),
		Values:                       make([]Value, 0, 64),
		ListValues:                   make([]ListValue, 0, 4),
		ObjectFields:                 make([]ObjectField, 0, 64),
		ObjectValues:                 make([]ObjectValue, 0, 16),
		Selections:                   make([]Selection, 0, 128),
		SelectionSets:                make([]SelectionSet, 0, 48),
		Fields:                       make([]Field, 0, 128),
		InlineFragments:              make([]InlineFragment, 0, 16),
		FragmentSpreads:              make([]FragmentSpread, 0, 16),
		OperationDefinitions:         make([]OperationDefinition, 0, 8),
		VariableDefinitions:          make([]VariableDefinition, 0, 8),
		FragmentDefinitions:          make([]FragmentDefinition, 0, 8),
		BooleanValues:                [2]BooleanValue{false, true},
		Refs:                         make([][8]int, 48),
		RefIndex:                     -1,
		Index: Index{
			Nodes: make(map[uint64]Node, 48),
		},
	}
}

func (d *Document) Reset() {
	d.RootNodes = d.RootNodes[:0]
	d.SchemaDefinitions = d.SchemaDefinitions[:0]
	d.SchemaExtensions = d.SchemaExtensions[:0]
	d.RootOperationTypeDefinitions = d.RootOperationTypeDefinitions[:0]
	d.Directives = d.Directives[:0]
	d.Arguments = d.Arguments[:0]
	d.ObjectTypeDefinitions = d.ObjectTypeDefinitions[:0]
	d.ObjectTypeExtensions = d.ObjectTypeExtensions[:0]
	d.Types = d.Types[:0]
	d.FieldDefinitions = d.FieldDefinitions[:0]
	d.InputValueDefinitions = d.InputValueDefinitions[:0]
	d.InputObjectTypeDefinitions = d.InputObjectTypeDefinitions[:0]
	d.InputObjectTypeExtensions = d.InputObjectTypeExtensions[:0]
	d.ScalarTypeDefinitions = d.ScalarTypeDefinitions[:0]
	d.ScalarTypeExtensions = d.ScalarTypeExtensions[:0]
	d.InterfaceTypeDefinitions = d.InterfaceTypeDefinitions[:0]
	d.InterfaceTypeExtensions = d.InterfaceTypeExtensions[:0]
	d.UnionTypeDefinitions = d.UnionTypeDefinitions[:0]
	d.UnionTypeExtensions = d.UnionTypeExtensions[:0]
	d.EnumTypeDefinitions = d.EnumTypeDefinitions[:0]
	d.EnumTypeExtensions = d.EnumTypeExtensions[:0]
	d.EnumValueDefinitions = d.EnumValueDefinitions[:0]
	d.DirectiveDefinitions = d.DirectiveDefinitions[:0]
	d.VariableValues = d.VariableValues[:0]
	d.StringValues = d.StringValues[:0]
	d.EnumValues = d.EnumValues[:0]
	d.IntValues = d.IntValues[:0]
	d.FloatValues = d.FloatValues[:0]
	d.Values = d.Values[:0]
	d.ListValues = d.ListValues[:0]
	d.ObjectFields = d.ObjectFields[:0]
	d.ObjectValues = d.ObjectValues[:0]
	d.Selections = d.Selections[:0]
	d.SelectionSets = d.SelectionSets[:0]
	d.Fields = d.Fields[:0]
	d.InlineFragments = d.InlineFragments[:0]
	d.FragmentSpreads = d.FragmentSpreads[:0]
	d.OperationDefinitions = d.OperationDefinitions[:0]
	d.VariableDefinitions = d.VariableDefinitions[:0]
	d.FragmentDefinitions = d.FragmentDefinitions[:0]

	d.RefIndex = -1
	d.Index.Reset()
}

func (d *Document) NextRefIndex() int {
	d.RefIndex++
	if d.RefIndex == len(d.Refs) {
		d.Refs = append(d.Refs, [8]int{})
	}
	return d.RefIndex
}

func (d *Document) FragmentDefinitionRef(byName ByteSlice) (ref int, exists bool) {
	for i := range d.FragmentDefinitions {
		if bytes.Equal(byName, d.Input.ByteSlice(d.FragmentDefinitions[i].Name)) {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) DeleteRootNodes(nodes []Node) {
	for i := range nodes {
		d.DeleteRootNode(nodes[i])
	}
}

func (d *Document) DeleteRootNode(node Node) {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == node.Kind && d.RootNodes[i].Ref == node.Ref {
			d.RootNodes = append(d.RootNodes[:i], d.RootNodes[i+1:]...)
			return
		}
	}
}

func (d *Document) NodeIsLastRootNode(node Node) bool {
	if len(d.RootNodes) == 0 {
		return false
	}
	return d.RootNodes[len(d.RootNodes)-1] == node
}

// NodeResolverTypeNameBytes returns lowercase query/mutation/subscription for Query/Mutation/Subscription
// for other type definitions it returns the default type name
func (d *Document) NodeResolverTypeNameBytes(node Node, path Path) ByteSlice {
	if len(path) == 1 && path[0].Kind == FieldName {
		return path[0].FieldName
	}
	switch node.Kind {
	case NodeKindObjectTypeDefinition:
		return d.ObjectTypeDefinitionNameBytes(node.Ref)
	case NodeKindInterfaceTypeDefinition:
		return d.InterfaceTypeDefinitionNameBytes(node.Ref)
	case NodeKindUnionTypeDefinition:
		return d.UnionTypeDefinitionNameBytes(node.Ref)
	}
	return nil
}

func (d *Document) NodeResolverTypeNameString(node Node, path Path) string {
	return unsafebytes.BytesToString(d.NodeResolverTypeNameBytes(node, path))
}

func (d *Document) NodeNameBytes(node Node) ByteSlice {

	var ref ByteSliceReference

	switch node.Kind {
	case NodeKindObjectTypeDefinition:
		ref = d.ObjectTypeDefinitions[node.Ref].Name
	case NodeKindInterfaceTypeDefinition:
		ref = d.InterfaceTypeDefinitions[node.Ref].Name
	case NodeKindInputObjectTypeDefinition:
		ref = d.InputObjectTypeDefinitions[node.Ref].Name
	case NodeKindUnionTypeDefinition:
		ref = d.UnionTypeDefinitions[node.Ref].Name
	case NodeKindScalarTypeDefinition:
		ref = d.ScalarTypeDefinitions[node.Ref].Name
	case NodeKindDirectiveDefinition:
		ref = d.DirectiveDefinitions[node.Ref].Name
	case NodeKindField:
		ref = d.Fields[node.Ref].Name
	case NodeKindDirective:
		ref = d.Directives[node.Ref].Name
	}

	return d.Input.ByteSlice(ref)
}

func (d *Document) NodeKindNameBytes(node Node) ByteSlice {
	switch node.Kind {
	case NodeKindOperationDefinition:
		switch d.OperationDefinitions[node.Ref].OperationType {
		case OperationTypeQuery:
			return literal.LocationQuery
		case OperationTypeMutation:
			return literal.LocationMutation
		case OperationTypeSubscription:
			return literal.LocationSubscription
		}
	case NodeKindField:
		return literal.LocationField
	case NodeKindFragmentDefinition:
		return literal.LocationFragmentDefinition
	case NodeKindFragmentSpread:
		return literal.LocationFragmentSpread
	case NodeKindInlineFragment:
		return literal.LocationInlineFragment
	case NodeKindVariableDefinition:
		return literal.LocationVariableDefinition
	case NodeKindSchemaDefinition:
		return literal.LocationSchema
	case NodeKindScalarTypeDefinition:
		return literal.LocationScalar
	case NodeKindObjectTypeDefinition:
		return literal.LocationObject
	case NodeKindFieldDefinition:
		return literal.LocationFieldDefinition
	case NodeKindInterfaceTypeDefinition:
		return literal.LocationInterface
	case NodeKindUnionTypeDefinition:
		return literal.LocationUnion
	case NodeKindEnumTypeDefinition:
		return literal.LocationEnum
	case NodeKindEnumValueDefinition:
		return literal.LocationEnumValue
	case NodeKindInputObjectTypeDefinition:
		return literal.LocationInputObject
	case NodeKindInputValueDefinition:
		return literal.LocationInputFieldDefinition
	}

	return unsafebytes.StringToBytes(node.Kind.String())
}

func (d *Document) FieldDefinitionArgumentsDefinitions(ref int) []int {
	return d.FieldDefinitions[ref].ArgumentsDefinition.Refs
}

func (d *Document) NodeFieldDefinitionArgumentDefinitionByName(node Node, fieldName, argumentName ByteSlice) int {
	fieldDefinition, exists := d.NodeFieldDefinitionByName(node, fieldName)
	if !exists {
		return -1
	}
	argumentDefinitions := d.FieldDefinitionArgumentsDefinitions(fieldDefinition)
	for _, i := range argumentDefinitions {
		if bytes.Equal(argumentName, d.Input.ByteSlice(d.InputValueDefinitions[i].Name)) {
			return i
		}
	}
	return -1
}

func (d *Document) NodeFieldDefinitionArgumentsDefinitions(node Node, fieldName ByteSlice) []int {
	fieldDefinition, exists := d.NodeFieldDefinitionByName(node, fieldName)
	if !exists {
		return nil
	}
	return d.FieldDefinitionArgumentsDefinitions(fieldDefinition)
}

func (d *Document) FieldDefinitionType(ref int) int {
	return d.FieldDefinitions[ref].Type
}

func (d *Document) FieldDefinitionTypeNode(ref int) Node {
	typeName := d.ResolveTypeName(d.FieldDefinitions[ref].Type)
	return d.Index.Nodes[xxhash.Sum64(typeName)]
}

func (d *Document) ExtendInterfaceTypeDefinitionByInterfaceTypeExtension(interfaceTypeDefinitionRef, interfaceTypeExtensionRef int) {
	if d.InterfaceTypeExtensionHasFieldDefinitions(interfaceTypeExtensionRef) {
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].FieldsDefinition.Refs = append(d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].FieldsDefinition.Refs, d.InterfaceTypeExtensions[interfaceTypeExtensionRef].FieldsDefinition.Refs...)
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].HasFieldDefinitions = true
	}

	if d.InterfaceTypeExtensionHasDirectives(interfaceTypeExtensionRef) {
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].Directives.Refs = append(d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].Directives.Refs, d.InterfaceTypeExtensions[interfaceTypeExtensionRef].Directives.Refs...)
		d.InterfaceTypeDefinitions[interfaceTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: interfaceTypeExtensionRef, Kind: NodeKindInterfaceTypeExtension})
}

func (d *Document) ExtendObjectTypeDefinitionByObjectTypeExtension(objectTypeDefinitionRef, objectTypeExtensionRef int) {
	if d.ObjectTypeExtensionHasFieldDefinitions(objectTypeExtensionRef) {
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs = append(d.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs, d.ObjectTypeExtensions[objectTypeExtensionRef].FieldsDefinition.Refs...)
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].HasFieldDefinitions = true
	}

	if d.ObjectTypeExtensionHasDirectives(objectTypeExtensionRef) {
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].Directives.Refs = append(d.ObjectTypeDefinitions[objectTypeDefinitionRef].Directives.Refs, d.ObjectTypeExtensions[objectTypeExtensionRef].Directives.Refs...)
		d.ObjectTypeDefinitions[objectTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: objectTypeExtensionRef, Kind: NodeKindObjectTypeExtension})
}

func (d *Document) ExtendScalarTypeDefinitionByScalarTypeExtension(scalarTypeDefinitionRef, scalarTypeExtensionRef int) {
	if d.ScalarTypeExtensionHasDirectives(scalarTypeExtensionRef) {
		d.ScalarTypeDefinitions[scalarTypeDefinitionRef].Directives.Refs = append(d.ScalarTypeDefinitions[scalarTypeDefinitionRef].Directives.Refs, d.ScalarTypeExtensions[scalarTypeExtensionRef].Directives.Refs...)
		d.ScalarTypeDefinitions[scalarTypeDefinitionRef].HasDirectives = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: scalarTypeExtensionRef, Kind: NodeKindScalarTypeExtension})
}

func (d *Document) ExtendUnionTypeDefinitionByUnionTypeExtension(unionTypeDefinitionRef, unionTypeExtensionRef int) {
	if d.UnionTypeExtensionHasDirectives(unionTypeExtensionRef) {
		d.UnionTypeDefinitions[unionTypeDefinitionRef].Directives.Refs = append(d.UnionTypeDefinitions[unionTypeDefinitionRef].Directives.Refs, d.UnionTypeExtensions[unionTypeExtensionRef].Directives.Refs...)
		d.UnionTypeDefinitions[unionTypeDefinitionRef].HasDirectives = true
	}

	if d.UnionTypeExtensionHasUnionMemberTypes(unionTypeExtensionRef) {
		d.UnionTypeDefinitions[unionTypeDefinitionRef].UnionMemberTypes.Refs = append(d.UnionTypeDefinitions[unionTypeDefinitionRef].UnionMemberTypes.Refs, d.UnionTypeExtensions[unionTypeExtensionRef].UnionMemberTypes.Refs...)
		d.UnionTypeDefinitions[unionTypeDefinitionRef].HasUnionMemberTypes = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: unionTypeExtensionRef, Kind: NodeKindUnionTypeExtension})
}

func (d *Document) ExtendEnumTypeDefinitionByEnumTypeExtension(enumTypeDefinitionRef, enumTypeExtensionRef int) {
	if d.EnumTypeExtensionHasDirectives(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].Directives.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].Directives.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasDirectives = true
	}

	if d.EnumTypeDefinitionHasEnumValueDefinition(enumTypeExtensionRef) {
		d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs = append(d.EnumTypeDefinitions[enumTypeDefinitionRef].EnumValuesDefinition.Refs, d.EnumTypeExtensions[enumTypeExtensionRef].EnumValuesDefinition.Refs...)
		d.EnumTypeDefinitions[enumTypeDefinitionRef].HasEnumValuesDefinition = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: enumTypeExtensionRef, Kind: NodeKindEnumTypeExtension})
}

func (d *Document) ExtendInputObjectTypeDefinitionByInputObjectTypeExtension(inputObjectTypeDefinitionRef, inputObjectTypeExtensionRef int) {
	if d.InputObjectTypeExtensionHasDirectives(inputObjectTypeExtensionRef) {
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].Directives.Refs = append(d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].Directives.Refs, d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].Directives.Refs...)
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].HasDirectives = true
	}

	if d.InputObjectTypeExtensionHasInputFieldsDefinition(inputObjectTypeExtensionRef) {
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].InputFieldsDefinition.Refs = append(d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].InputFieldsDefinition.Refs, d.InputObjectTypeExtensions[inputObjectTypeExtensionRef].InputFieldsDefinition.Refs...)
		d.InputObjectTypeDefinitions[inputObjectTypeDefinitionRef].HasInputFieldsDefinition = true
	}

	d.Index.MergedTypeExtensions = append(d.Index.MergedTypeExtensions, Node{Ref: inputObjectTypeExtensionRef, Kind: NodeKindInputObjectTypeExtension})
}

func (d *Document) RemoveMergedTypeExtensions() {
	for _, node := range d.Index.MergedTypeExtensions {
		d.RemoveRootNode(node)
	}
}

func (d *Document) RemoveRootNode(node Node) {
	for i := range d.RootNodes {
		if d.RootNodes[i] == node {
			d.RootNodes = append(d.RootNodes[:i], d.RootNodes[i+1:]...)
			return
		}
	}
}

func (d *Document) NodeFieldDefinitions(node Node) []int {
	switch node.Kind {
	case NodeKindObjectTypeDefinition:
		return d.ObjectTypeDefinitions[node.Ref].FieldsDefinition.Refs
	case NodeKindObjectTypeExtension:
		return d.ObjectTypeExtensions[node.Ref].FieldsDefinition.Refs
	case NodeKindInterfaceTypeDefinition:
		return d.InterfaceTypeDefinitions[node.Ref].FieldsDefinition.Refs
	case NodeKindInterfaceTypeExtension:
		return d.InterfaceTypeExtensions[node.Ref].FieldsDefinition.Refs
	default:
		return nil
	}
}

func (d *Document) NodeFieldDefinitionByName(node Node, fieldName ByteSlice) (definition int, exists bool) {
	for _, i := range d.NodeFieldDefinitions(node) {
		if bytes.Equal(d.Input.ByteSlice(d.FieldDefinitions[i].Name), fieldName) {
			return i, true
		}
	}
	return
}

func (d *Document) NodeNameString(node Node) string {
	return unsafebytes.BytesToString(d.NodeNameBytes(node))
}

func (d *Document) FieldAliasBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Fields[ref].Alias.Name)
}

func (d *Document) FieldAliasString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.Fields[ref].Alias.Name))
}

func (d *Document) FieldAliasIsDefined(ref int) bool {
	return d.Fields[ref].Alias.IsDefined
}

func (d *Document) FragmentSpreadNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FragmentSpreads[ref].FragmentName)
}

func (d *Document) FragmentSpreadNameString(ref int) string {
	return unsafebytes.BytesToString(d.FragmentSpreadNameBytes(ref))
}

func (d *Document) InlineFragmentTypeConditionName(ref int) ByteSlice {
	if d.InlineFragments[ref].TypeCondition.Type == -1 {
		return nil
	}
	return d.Input.ByteSlice(d.Types[d.InlineFragments[ref].TypeCondition.Type].Name)
}

func (d *Document) InlineFragmentTypeConditionNameString(ref int) string {
	return unsafebytes.BytesToString(d.InlineFragmentTypeConditionName(ref))
}

func (d *Document) FragmentDefinitionTypeName(ref int) ByteSlice {
	return d.ResolveTypeName(d.FragmentDefinitions[ref].TypeCondition.Type)
}

func (d *Document) ResolveTypeName(ref int) ByteSlice {
	graphqlType := d.Types[ref]
	for graphqlType.TypeKind != TypeKindNamed {
		graphqlType = d.Types[graphqlType.OfType]
	}
	return d.Input.ByteSlice(graphqlType.Name)
}

func (d *Document) PrintSelections(selections []int) (out string) {
	out += "["
	for i, ref := range selections {
		out += fmt.Sprintf("%+v", d.Selections[ref])
		if i != len(selections)-1 {
			out += ","
		}
	}
	out += "]"
	return
}

func (d *Document) NodeImplementsInterface(node Node, interfaceNode Node) bool {

	nodeFields := d.NodeFieldDefinitions(node)
	interfaceFields := d.NodeFieldDefinitions(interfaceNode)

	for _, i := range interfaceFields {
		interfaceFieldName := d.FieldDefinitionNameBytes(i)
		if !d.FieldDefinitionsContainField(nodeFields, interfaceFieldName) {
			return false
		}
	}

	return true
}

func (d *Document) FieldDefinitionsContainField(definitions []int, field ByteSlice) bool {
	for _, i := range definitions {
		if bytes.Equal(field, d.FieldDefinitionNameBytes(i)) {
			return true
		}
	}
	return false
}

func (d *Document) NodeByName(name ByteSlice) (Node, bool) {
	node, exists := d.Index.Nodes[xxhash.Sum64(name)]
	return node, exists
}

func (d *Document) FieldHasArguments(ref int) bool {
	return d.Fields[ref].HasArguments
}

func (d *Document) FieldHasSelections(ref int) bool {
	return d.Fields[ref].HasSelections
}

func (d *Document) FieldHasDirectives(ref int) bool {
	return d.Fields[ref].HasDirectives
}

func (d *Document) BooleanValue(ref int) BooleanValue {
	return d.BooleanValues[ref]
}

func (d *Document) BooleanValuesAreEqual(left, right int) bool {
	return d.BooleanValue(left) == d.BooleanValue(right)
}

func (d *Document) StringValue(ref int) StringValue {
	return d.StringValues[ref]
}

func (d *Document) StringValueContentBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.StringValues[ref].Content)
}

func (d *Document) StringValueContentString(ref int) string {
	return unsafebytes.BytesToString(d.StringValueContentBytes(ref))
}

func (d *Document) StringValueIsBlockString(ref int) bool {
	return d.StringValues[ref].BlockString
}

func (d *Document) StringValuesAreEquals(left, right int) bool {
	return d.StringValueIsBlockString(left) == d.StringValueIsBlockString(right) &&
		bytes.Equal(d.StringValueContentBytes(left), d.StringValueContentBytes(right))
}

func (d *Document) IntValue(ref int) IntValue {
	return d.IntValues[ref]
}

func (d *Document) IntValueIsNegative(ref int) bool {
	return d.IntValues[ref].Negative
}

func (d *Document) IntValueRaw(ref int) ByteSlice {
	return d.Input.ByteSlice(d.IntValues[ref].Raw)
}

func (d *Document) IntValuesAreEquals(left, right int) bool {
	return d.IntValueIsNegative(left) == d.IntValueIsNegative(right) &&
		bytes.Equal(d.IntValueRaw(left), d.IntValueRaw(right))
}

func (d *Document) FloatValueIsNegative(ref int) bool {
	return d.FloatValues[ref].Negative
}

func (d *Document) FloatValueRaw(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FloatValues[ref].Raw)
}

func (d *Document) FloatValuesAreEqual(left, right int) bool {
	return d.FloatValueIsNegative(left) == d.FloatValueIsNegative(right) &&
		bytes.Equal(d.FloatValueRaw(left), d.FloatValueRaw(right))
}

func (d *Document) VariableValueNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.VariableValues[ref].Name)
}

func (d *Document) VariableValuesAreEqual(left, right int) bool {
	return bytes.Equal(d.VariableValueNameBytes(left), d.VariableValueNameBytes(right))
}

func (d *Document) Value(ref int) Value {
	return d.Values[ref]
}

func (d *Document) ListValuesAreEqual(left, right int) bool {
	leftValues, rightValues := d.ListValues[left].Refs, d.ListValues[right].Refs
	if len(leftValues) != len(rightValues) {
		return false
	}
	for i := 0; i < len(leftValues); i++ {
		left, right = leftValues[i], rightValues[i]
		leftValue, rightValue := d.Value(left), d.Value(right)
		if !d.ValuesAreEqual(leftValue, rightValue) {
			return false
		}
	}
	return true
}

func (d *Document) ObjectField(ref int) ObjectField {
	return d.ObjectFields[ref]
}

func (d *Document) ObjectFieldNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ObjectFields[ref].Name)
}

func (d *Document) ObjectFieldValue(ref int) Value {
	return d.ObjectFields[ref].Value
}

func (d *Document) ObjectFieldsAreEqual(left, right int) bool {
	return bytes.Equal(d.ObjectFieldNameBytes(left), d.ObjectFieldNameBytes(right)) &&
		d.ValuesAreEqual(d.ObjectFieldValue(left), d.ObjectFieldValue(right))
}

func (d *Document) ObjectValuesAreEqual(left, right int) bool {
	leftFields, rightFields := d.ObjectValues[left].Refs, d.ObjectValues[right].Refs
	if len(leftFields) != len(rightFields) {
		return false
	}
	for i := 0; i < len(leftFields); i++ {
		left, right = leftFields[i], rightFields[i]
		if !d.ObjectFieldsAreEqual(left, right) {
			return false
		}
	}
	return true
}

func (d *Document) EnumValueName(ref int) ByteSliceReference {
	return d.EnumValues[ref].Name
}

func (d *Document) EnumValueNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumValues[ref].Name)
}

func (d *Document) EnumValueNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumValues[ref].Name))
}

func (d *Document) EnumValuesAreEqual(left, right int) bool {
	return d.Input.ByteSliceReferenceContentEquals(d.EnumValueName(left), d.EnumValueName(right))
}

func (d *Document) ValuesAreEqual(left, right Value) bool {
	if left.Kind != right.Kind {
		return false
	}
	switch left.Kind {
	case ValueKindString:
		return d.StringValuesAreEquals(left.Ref, right.Ref)
	case ValueKindBoolean:
		return d.BooleanValuesAreEqual(left.Ref, right.Ref)
	case ValueKindInteger:
		return d.IntValuesAreEquals(left.Ref, right.Ref)
	case ValueKindFloat:
		return d.FloatValuesAreEqual(left.Ref, right.Ref)
	case ValueKindVariable:
		return d.VariableValuesAreEqual(left.Ref, right.Ref)
	case ValueKindNull:
		return true
	case ValueKindList:
		return d.ListValuesAreEqual(left.Ref, right.Ref)
	case ValueKindObject:
		return d.ObjectValuesAreEqual(left.Ref, right.Ref)
	case ValueKindEnum:
		return d.EnumValuesAreEqual(left.Ref, right.Ref)
	default:
		return false
	}
}

func (d *Document) ArgumentNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Arguments[ref].Name)
}

func (d *Document) ArgumentNameString(ref int) string {
	return unsafebytes.BytesToString(d.ArgumentNameBytes(ref))
}

func (d *Document) ArgumentValue(ref int) Value {
	return d.Arguments[ref].Value
}

func (d *Document) ArgumentsAreEqual(left, right int) bool {
	return bytes.Equal(d.ArgumentNameBytes(left), d.ArgumentNameBytes(right)) &&
		d.ValuesAreEqual(d.ArgumentValue(left), d.ArgumentValue(right))
}

func (d *Document) ArgumentSetsAreEquals(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		leftArgument, rightArgument := left[i], right[i]
		if !d.ArgumentsAreEqual(leftArgument, rightArgument) {
			return false
		}
	}
	return true
}

func (d *Document) FieldArguments(ref int) []int {
	return d.Fields[ref].Arguments.Refs
}

func (d *Document) FieldArgument(field int, name ByteSlice) (ref int, exists bool) {
	for _, i := range d.Fields[field].Arguments.Refs {
		if bytes.Equal(d.ArgumentNameBytes(i), name) {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) FieldDirectives(ref int) []int {
	return d.Fields[ref].Directives.Refs
}

func (d *Document) DirectiveName(ref int) ByteSliceReference {
	return d.Directives[ref].Name
}

func (d *Document) DirectiveNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Directives[ref].Name)
}

func (d *Document) DirectiveIsFirst(directive int, ancestor Node) bool {
	directives := d.NodeDirectives(ancestor)
	return len(directives) != 0 && directives[0] == directive
}

func (d *Document) DirectiveIsLast(directive int, ancestor Node) bool {
	directives := d.NodeDirectives(ancestor)
	return len(directives) != 0 && directives[len(directives)-1] == directive
}

func (d *Document) DirectiveNameString(ref int) string {
	return d.Input.ByteSliceString(d.Directives[ref].Name)
}

func (d *Document) DirectiveArgumentSet(ref int) []int {
	return d.Directives[ref].Arguments.Refs
}

func (d *Document) DirectiveArgumentValueByName(ref int, name ByteSlice) (Value, bool) {
	for i := 0; i < len(d.Directives[ref].Arguments.Refs); i++ {
		arg := d.Directives[ref].Arguments.Refs[i]
		if bytes.Equal(d.ArgumentNameBytes(arg), name) {
			return d.ArgumentValue(arg), true
		}
	}
	return Value{}, false
}

func (d *Document) DirectivesAreEqual(left, right int) bool {
	return d.Input.ByteSliceReferenceContentEquals(d.DirectiveName(left), d.DirectiveName(right)) &&
		d.ArgumentSetsAreEquals(d.DirectiveArgumentSet(left), d.DirectiveArgumentSet(right))
}

func (d *Document) DirectiveSetsAreEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		leftDirective, rightDirective := left[i], right[i]
		if !d.DirectivesAreEqual(leftDirective, rightDirective) {
			return false
		}
	}
	return true
}

func (d *Document) FieldsAreEqualFlat(left, right int) bool {
	return bytes.Equal(d.FieldNameBytes(left), d.FieldNameBytes(right)) && // name
		bytes.Equal(d.FieldAliasBytes(left), d.FieldAliasBytes(right)) && // alias
		!d.FieldHasSelections(left) && !d.FieldHasSelections(right) && // selections
		d.ArgumentSetsAreEquals(d.FieldArguments(left), d.FieldArguments(right)) && // arguments
		d.DirectiveSetsAreEqual(d.FieldDirectives(left), d.FieldDirectives(right)) // directives
}

func (d *Document) InlineFragmentHasTypeCondition(ref int) bool {
	return d.InlineFragments[ref].TypeCondition.Type != -1
}

func (d *Document) InlineFragmentHasDirectives(ref int) bool {
	return len(d.InlineFragments[ref].Directives.Refs) != 0
}

func (d *Document) TypeDefinitionContainsImplementsInterface(typeName, interfaceName ByteSlice) bool {
	typeDefinition, exists := d.Index.Nodes[xxhash.Sum64(typeName)]
	if !exists {
		return false
	}
	if typeDefinition.Kind != NodeKindObjectTypeDefinition {
		return false
	}
	for _, i := range d.ObjectTypeDefinitions[typeDefinition.Ref].ImplementsInterfaces.Refs {
		implements := d.ResolveTypeName(i)
		if bytes.Equal(interfaceName, implements) {
			return true
		}
	}
	return false
}

func (d *Document) RemoveFieldAlias(ref int) {
	d.Fields[ref].Alias.IsDefined = false
	d.Fields[ref].Alias.Name.Start = 0
	d.Fields[ref].Alias.Name.End = 0
}

func (d *Document) InlineFragmentSelections(ref int) []int {
	if !d.InlineFragments[ref].HasSelections {
		return nil
	}
	return d.SelectionSets[d.InlineFragments[ref].SelectionSet].SelectionRefs
}

func (d *Document) TypesAreEqualDeep(left int, right int) bool {
	for {
		if left == -1 || right == -1 {
			return false
		}
		if d.Types[left].TypeKind != d.Types[right].TypeKind {
			return false
		}
		if d.Types[left].TypeKind == TypeKindNamed {
			leftName := d.TypeNameBytes(left)
			rightName := d.TypeNameBytes(right)
			return bytes.Equal(leftName, rightName)
		}
		left = d.Types[left].OfType
		right = d.Types[right].OfType
	}
}

func (d *Document) TypeIsList(ref int) bool {
	switch d.Types[ref].TypeKind {
	case TypeKindList:
		return true
	case TypeKindNonNull:
		return d.TypeIsList(d.Types[ref].OfType)
	default:
		return false
	}
}

func (d *Document) TypesAreCompatibleDeep(left int, right int) bool {
	for {
		if left == -1 || right == -1 {
			return false
		}
		if d.Types[left].TypeKind != d.Types[right].TypeKind {
			return false
		}
		if d.Types[left].TypeKind == TypeKindNamed {
			leftName := d.TypeNameBytes(left)
			rightName := d.TypeNameBytes(right)
			if bytes.Equal(leftName, rightName) {
				return true
			}
			leftNode := d.Index.Nodes[xxhash.Sum64(leftName)]
			rightNode := d.Index.Nodes[xxhash.Sum64(rightName)]
			if leftNode.Kind == rightNode.Kind {
				return false
			}
			if leftNode.Kind == NodeKindInterfaceTypeDefinition && rightNode.Kind == NodeKindObjectTypeDefinition {
				return d.NodeImplementsInterface(rightNode, leftNode)
			}
			if leftNode.Kind == NodeKindObjectTypeDefinition && rightNode.Kind == NodeKindInterfaceTypeDefinition {
				return d.NodeImplementsInterface(leftNode, rightNode)
			}
			if leftNode.Kind == NodeKindUnionTypeDefinition && rightNode.Kind == NodeKindObjectTypeDefinition {
				return d.NodeIsUnionMember(rightNode, leftNode)
			}
			if leftNode.Kind == NodeKindObjectTypeDefinition && rightNode.Kind == NodeKindUnionTypeDefinition {
				return d.NodeIsUnionMember(leftNode, rightNode)
			}
			return false
		}
		left = d.Types[left].OfType
		right = d.Types[right].OfType
	}
}

func (d *Document) FieldsHaveSameShape(left, right int) bool {

	leftAliasDefined := d.FieldAliasIsDefined(left)
	rightAliasDefined := d.FieldAliasIsDefined(right)

	switch {
	case !leftAliasDefined && !rightAliasDefined:
		return d.Input.ByteSliceReferenceContentEquals(d.Fields[left].Name, d.Fields[right].Name)
	case leftAliasDefined && rightAliasDefined:
		return d.Input.ByteSliceReferenceContentEquals(d.Fields[left].Alias.Name, d.Fields[right].Alias.Name)
	case leftAliasDefined && !rightAliasDefined:
		return d.Input.ByteSliceReferenceContentEquals(d.Fields[left].Alias.Name, d.Fields[right].Name)
	case !leftAliasDefined && rightAliasDefined:
		return d.Input.ByteSliceReferenceContentEquals(d.Fields[left].Name, d.Fields[right].Alias.Name)
	default:
		return false
	}
}

func (d *Document) NodeFragmentIsAllowedOnNode(fragmentNode, onNode Node) bool {
	switch onNode.Kind {
	case NodeKindObjectTypeDefinition:
		return d.NodeFragmentIsAllowedOnObjectTypeDefinition(fragmentNode, onNode)
	case NodeKindInterfaceTypeDefinition:
		return d.NodeFragmentIsAllowedOnInterfaceTypeDefinition(fragmentNode, onNode)
	case NodeKindUnionTypeDefinition:
		return d.NodeFragmentIsAllowedOnUnionTypeDefinition(fragmentNode, onNode)
	default:
		return false
	}
}

func (d *Document) NodeFragmentIsAllowedOnInterfaceTypeDefinition(fragmentNode, interfaceTypeNode Node) bool {

	switch fragmentNode.Kind {
	case NodeKindObjectTypeDefinition:
		return d.NodeImplementsInterface(fragmentNode, interfaceTypeNode)
	case NodeKindInterfaceTypeDefinition:
		return bytes.Equal(d.InterfaceTypeDefinitionNameBytes(fragmentNode.Ref), d.InterfaceTypeDefinitionNameBytes(interfaceTypeNode.Ref))
	case NodeKindUnionTypeDefinition:
		return d.UnionNodeIntersectsInterfaceNode(fragmentNode, interfaceTypeNode)
	}

	return false
}

func (d *Document) NodeFragmentIsAllowedOnUnionTypeDefinition(fragmentNode, unionTypeNode Node) bool {

	switch fragmentNode.Kind {
	case NodeKindObjectTypeDefinition:
		return d.NodeIsUnionMember(fragmentNode, unionTypeNode)
	case NodeKindInterfaceTypeDefinition:
		return false
	case NodeKindUnionTypeDefinition:
		return bytes.Equal(d.UnionTypeDefinitionNameBytes(fragmentNode.Ref), d.UnionTypeDefinitionNameBytes(unionTypeNode.Ref))
	}

	return false
}

func (d *Document) NodeFragmentIsAllowedOnObjectTypeDefinition(fragmentNode, objectTypeNode Node) bool {

	switch fragmentNode.Kind {
	case NodeKindObjectTypeDefinition:
		return bytes.Equal(d.ObjectTypeDefinitionNameBytes(fragmentNode.Ref), d.ObjectTypeDefinitionNameBytes(objectTypeNode.Ref))
	case NodeKindInterfaceTypeDefinition:
		return d.NodeImplementsInterface(objectTypeNode, fragmentNode)
	case NodeKindUnionTypeDefinition:
		return d.NodeIsUnionMember(objectTypeNode, fragmentNode)
	}

	return false
}

func (d *Document) UnionNodeIntersectsInterfaceNode(unionNode, interfaceNode Node) bool {
	for _, i := range d.UnionTypeDefinitions[unionNode.Ref].UnionMemberTypes.Refs {
		memberName := d.ResolveTypeName(i)
		node := d.Index.Nodes[xxhash.Sum64(memberName)]
		if node.Kind != NodeKindObjectTypeDefinition {
			continue
		}
		if d.NodeImplementsInterface(node, interfaceNode) {
			return true
		}
	}
	return false
}

func (d *Document) NodeIsUnionMember(node Node, union Node) bool {
	nodeTypeName := d.NodeNameBytes(node)
	for _, i := range d.UnionTypeDefinitions[union.Ref].UnionMemberTypes.Refs {
		memberName := d.ResolveTypeName(i)
		if bytes.Equal(nodeTypeName, memberName) {
			return true
		}
	}
	return false
}

type Node struct {
	Kind NodeKind
	Ref  int
}

func (d *Document) RemoveNodeFromNode(remove, from Node) {
	switch from.Kind {
	case NodeKindSelectionSet:
		d.RemoveNodeFromSelectionSet(from.Ref, remove)
	default:
		log.Printf("RemoveNodeFromNode not implemented for from: %s", from.Kind)
	}
}

func (d *Document) RemoveNodeFromSelectionSet(set int, node Node) {

	var selectionKind SelectionKind

	switch node.Kind {
	case NodeKindFragmentSpread:
		selectionKind = SelectionKindFragmentSpread
	case NodeKindInlineFragment:
		selectionKind = SelectionKindInlineFragment
	case NodeKindField:
		selectionKind = SelectionKindField
	default:
		log.Printf("RemoveNodeFromSelectionSet not implemented for node: %s", node.Kind)
		return
	}

	for i, j := range d.SelectionSets[set].SelectionRefs {
		if d.Selections[j].Kind == selectionKind && d.Selections[j].Ref == node.Ref {
			d.SelectionSets[set].SelectionRefs = append(d.SelectionSets[set].SelectionRefs[:i], d.SelectionSets[set].SelectionRefs[i+1:]...)
			return
		}
	}
}

func (n Node) Name(definition *Document) string {
	return unsafebytes.BytesToString(definition.NodeNameBytes(n))
}

type SchemaDefinition struct {
	SchemaLiteral                position.Position // schema
	HasDirectives                bool
	Directives                   DirectiveList                   // optional, e.g. @foo
	RootOperationTypeDefinitions RootOperationTypeDefinitionList // e.g. query: Query, mutation: Mutation, subscription: Subscription
}

func (s *SchemaDefinition) AddRootOperationTypeDefinitionRefs(refs ...int) {
	s.RootOperationTypeDefinitions.Refs = append(s.RootOperationTypeDefinitions.Refs, refs...)
}

func (d *Document) HasSchemaDefinition() bool {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindSchemaDefinition {
			return true
		}
	}

	return false
}

func (d *Document) AddSchemaDefinitionRootNode(schemaDefinition SchemaDefinition) {
	ref := d.AddSchemaDefinition(schemaDefinition)
	schemaNode := Node{
		Kind: NodeKindSchemaDefinition,
		Ref:  ref,
	}
	d.RootNodes = append([]Node{schemaNode}, d.RootNodes...)
}

func (d *Document) AddSchemaDefinition(schemaDefinition SchemaDefinition) (ref int) {
	d.SchemaDefinitions = append(d.SchemaDefinitions, schemaDefinition)
	return len(d.SchemaDefinitions) - 1
}

func (d *Document) NodeDirectives(node Node) []int {
	switch node.Kind {
	case NodeKindField:
		return d.Fields[node.Ref].Directives.Refs
	case NodeKindInlineFragment:
		return d.InlineFragments[node.Ref].Directives.Refs
	case NodeKindFragmentSpread:
		return d.FragmentSpreads[node.Ref].Directives.Refs
	case NodeKindSchemaDefinition:
		return d.SchemaDefinitions[node.Ref].Directives.Refs
	case NodeKindSchemaExtension:
		return d.SchemaExtensions[node.Ref].Directives.Refs
	case NodeKindObjectTypeDefinition:
		return d.ObjectTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindObjectTypeExtension:
		return d.ObjectTypeExtensions[node.Ref].Directives.Refs
	case NodeKindInterfaceTypeDefinition:
		return d.InterfaceTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindInterfaceTypeExtension:
		return d.InterfaceTypeExtensions[node.Ref].Directives.Refs
	case NodeKindInputObjectTypeDefinition:
		return d.InputObjectTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindInputObjectTypeExtension:
		return d.InputObjectTypeExtensions[node.Ref].Directives.Refs
	case NodeKindScalarTypeDefinition:
		return d.ScalarTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindScalarTypeExtension:
		return d.ScalarTypeExtensions[node.Ref].Directives.Refs
	case NodeKindUnionTypeDefinition:
		return d.UnionTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindUnionTypeExtension:
		return d.UnionTypeExtensions[node.Ref].Directives.Refs
	case NodeKindEnumTypeDefinition:
		return d.EnumTypeDefinitions[node.Ref].Directives.Refs
	case NodeKindEnumTypeExtension:
		return d.EnumTypeExtensions[node.Ref].Directives.Refs
	case NodeKindFragmentDefinition:
		return d.FragmentDefinitions[node.Ref].Directives.Refs
	case NodeKindInputValueDefinition:
		return d.InputValueDefinitions[node.Ref].Directives.Refs
	case NodeKindEnumValueDefinition:
		return d.EnumValueDefinitions[node.Ref].Directives.Refs
	case NodeKindVariableDefinition:
		return d.VariableDefinitions[node.Ref].Directives.Refs
	case NodeKindOperationDefinition:
		return d.OperationDefinitions[node.Ref].Directives.Refs
	default:
		return nil
	}
}

type DirectiveList struct {
	Refs []int
}

type RootOperationTypeDefinitionList struct {
	LBrace position.Position // {
	Refs   []int             // RootOperationTypeDefinition
	RBrace position.Position // }
}

type SchemaExtension struct {
	ExtendLiteral position.Position
	SchemaDefinition
}

type RootOperationTypeDefinition struct {
	OperationType OperationType     // one of query, mutation, subscription
	Colon         position.Position // :
	NamedType     Type              // e.g. Query
}

func (d *Document) RootOperationTypeDefinitionNameString(ref int) string {
	return d.RootOperationTypeDefinitions[ref].OperationType.String()
}

func (d *Document) RootOperationTypeDefinitionIsFirstInSchemaDefinition(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindSchemaDefinition:
		if len(d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs) == 0 {
			return false
		}
		return ref == d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs[0]
	case NodeKindSchemaExtension:
		if len(d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs) == 0 {
			return false
		}
		return ref == d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs[0]
	default:
		return false
	}
}

func (d *Document) RootOperationTypeDefinitionIsLastInSchemaDefinition(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindSchemaDefinition:
		return d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs[len(d.SchemaDefinitions[ancestor.Ref].RootOperationTypeDefinitions.Refs)-1] == ref
	case NodeKindSchemaExtension:
		return d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs[len(d.SchemaExtensions[ancestor.Ref].RootOperationTypeDefinitions.Refs)-1] == ref
	default:
		return false
	}
}

func (d *Document) CreateRootOperationTypeDefinition(operationType OperationType, rootNodeIndex int) (ref int) {
	switch operationType {
	case OperationTypeQuery:
		d.Index.QueryTypeName = []byte("Query")
	case OperationTypeMutation:
		d.Index.MutationTypeName = []byte("Mutation")
	case OperationTypeSubscription:
		d.Index.SubscriptionTypeName = []byte("Subscription")
	default:
		return
	}

	nameRef := d.ObjectTypeDefinitionNameRef(d.RootNodes[rootNodeIndex].Ref)
	return d.AddRootOperationTypeDefinition(RootOperationTypeDefinition{
		OperationType: operationType,
		NamedType: Type{
			TypeKind: TypeKindNamed,
			Name:     nameRef,
		},
	})
}

func (d *Document) AddRootOperationTypeDefinition(rootOperationTypeDefinition RootOperationTypeDefinition) (ref int) {
	d.RootOperationTypeDefinitions = append(d.RootOperationTypeDefinitions, rootOperationTypeDefinition)
	return len(d.RootOperationTypeDefinitions) - 1
}

type Directive struct {
	At           position.Position  // @
	Name         ByteSliceReference // e.g. include
	HasArguments bool
	Arguments    ArgumentList // e.g. (if: true)
}

func (d *Document) PrintDirective(ref int, w io.Writer) error {
	_, err := w.Write(literal.AT)
	if err != nil {
		return err
	}
	_, err = w.Write(d.Input.ByteSlice(d.Directives[ref].Name))
	if err != nil {
		return err
	}
	if d.Directives[ref].HasArguments {
		err = d.PrintArguments(d.Directives[ref].Arguments.Refs, w)
	}
	return err
}

type ArgumentList struct {
	LPAREN position.Position
	Refs   []int // Argument
	RPAREN position.Position
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

type InputValueDefinitionList struct {
	LPAREN position.Position // (
	Refs   []int             // InputValueDefinition
	RPAREN position.Position // )
}

type Argument struct {
	Name  ByteSliceReference // e.g. foo
	Colon position.Position  // :
	Value Value              // e.g. 100 or "Bar"
}

func (d *Document) ArgumentsBefore(ancestor Node, argument int) []int {
	switch ancestor.Kind {
	case NodeKindField:
		for i, j := range d.Fields[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Fields[ancestor.Ref].Arguments.Refs[:i]
			}
		}
	case NodeKindDirective:
		for i, j := range d.Directives[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Directives[ancestor.Ref].Arguments.Refs[:i]
			}
		}
	}
	return nil
}

func (d *Document) ArgumentsAfter(ancestor Node, argument int) []int {
	switch ancestor.Kind {
	case NodeKindField:
		for i, j := range d.Fields[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Fields[ancestor.Ref].Arguments.Refs[i+1:]
			}
		}
	case NodeKindDirective:
		for i, j := range d.Directives[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Directives[ancestor.Ref].Arguments.Refs[i+1:]
			}
		}
	}
	return nil
}

func (d *Document) PrintArgument(ref int, w io.Writer) error {
	_, err := w.Write(d.Input.ByteSlice(d.Arguments[ref].Name))
	if err != nil {
		return err
	}
	_, err = w.Write(literal.COLON)
	if err != nil {
		return err
	}
	_, err = w.Write(literal.SPACE)
	if err != nil {
		return err
	}
	return d.PrintValue(d.Arguments[ref].Value, w)
}

func (d *Document) PrintArguments(refs []int, w io.Writer) (err error) {
	_, err = w.Write(literal.LPAREN)
	if err != nil {
		return
	}
	for i, j := range refs {
		err = d.PrintArgument(j, w)
		if err != nil {
			return
		}
		if i != len(refs)-1 {
			_, err = w.Write(literal.COMMA)
			if err != nil {
				return
			}
			_, err = w.Write(literal.SPACE)
			if err != nil {
				return
			}
		}
	}
	_, err = w.Write(literal.RPAREN)
	return
}

type Value struct {
	Kind ValueKind // e.g. 100 or "Bar"
	Ref  int
}

func (d *Document) ValueContentBytes(value Value) ByteSlice {
	switch value.Kind {
	case ValueKindEnum:
		return d.EnumValueNameBytes(value.Ref)
	case ValueKindString:
		d.StringValueContentBytes(value.Ref)
	case ValueKindInteger:
		return d.IntValueRaw(value.Ref)
	case ValueKindFloat:
		return d.FloatValueRaw(value.Ref)
	}
	panic(fmt.Errorf("ValueContentBytes not implemented for ValueKind: %s", value.Kind))
}

// nolint
func (d *Document) PrintValue(value Value, w io.Writer) (err error) {
	switch value.Kind {
	case ValueKindBoolean:
		if d.BooleanValues[value.Ref] {
			_, err = w.Write(literal.TRUE)
		} else {
			_, err = w.Write(literal.FALSE)
		}
	case ValueKindString:
		_, err = w.Write(literal.QUOTE)
		_, err = w.Write(d.Input.ByteSlice(d.StringValues[value.Ref].Content))
		_, err = w.Write(literal.QUOTE)
	case ValueKindInteger:
		if d.IntValues[value.Ref].Negative {
			_, err = w.Write(literal.SUB)
		}
		_, err = w.Write(d.Input.ByteSlice(d.IntValues[value.Ref].Raw))
	case ValueKindFloat:
		if d.FloatValues[value.Ref].Negative {
			_, err = w.Write(literal.SUB)
		}
		_, err = w.Write(d.Input.ByteSlice(d.FloatValues[value.Ref].Raw))
	case ValueKindVariable:
		_, err = w.Write(literal.DOLLAR)
		_, err = w.Write(d.Input.ByteSlice(d.VariableValues[value.Ref].Name))
	case ValueKindNull:
		_, err = w.Write(literal.NULL)
	case ValueKindList:
		_, err = w.Write(literal.LBRACK)
		for i, j := range d.ListValues[value.Ref].Refs {
			err = d.PrintValue(d.Value(j), w)
			if err != nil {
				return
			}
			if i != len(d.ListValues[value.Ref].Refs)-1 {
				_, err = w.Write(literal.COMMA)
			}
		}
		_, err = w.Write(literal.RBRACK)
	case ValueKindObject:
		_, err = w.Write(literal.LBRACE)
		for i, j := range d.ObjectValues[value.Ref].Refs {
			_, err = w.Write(d.ObjectFieldNameBytes(j))
			if err != nil {
				return
			}
			_, err = w.Write(literal.COLON)
			if err != nil {
				return
			}
			_, err = w.Write(literal.SPACE)
			if err != nil {
				return
			}
			err = d.PrintValue(d.ObjectFieldValue(j), w)
			if err != nil {
				return
			}
			if i != len(d.ObjectValues[value.Ref].Refs)-1 {
				_, err = w.Write(literal.COMMA)
				if err != nil {
					return
				}
			}
		}
		_, err = w.Write(literal.RBRACE)
	case ValueKindEnum:
		_, err = w.Write(d.Input.ByteSlice(d.EnumValues[value.Ref].Name))
	}
	return
}

func (d *Document) PrintValueBytes(value Value, buf []byte) ([]byte, error) {
	if buf == nil {
		buf = make([]byte, 0, 24)
	}
	b := bytes.NewBuffer(buf)
	err := d.PrintValue(value, b)
	return b.Bytes(), err
}

type ListValue struct {
	LBRACK position.Position // [
	Refs   []int             // Value
	RBRACK position.Position // ]
}

// VariableValue
// example:
// $devicePicSize
type VariableValue struct {
	Dollar position.Position  // $
	Name   ByteSliceReference // e.g. devicePicSize
}

// StringValue
// example:
// "foo"
type StringValue struct {
	BlockString bool               // """foo""" = blockString, "foo" string
	Content     ByteSliceReference // e.g. foo
}

// IntValue
// example:
// 123 / -123
type IntValue struct {
	Negative     bool               // indicates if the value is negative
	NegativeSign position.Position  // optional -
	Raw          ByteSliceReference // e.g. 123
}

func (d *Document) IntValueAsInt(ref int) (out int64) {
	in := d.Input.ByteSlice(d.IntValues[ref].Raw)
	out = unsafebytes.BytesToInt64(in)
	if d.IntValues[ref].Negative {
		out = -out
	}
	return
}

// FloatValue
// example:
// 13.37 / -13.37
type FloatValue struct {
	Negative     bool               // indicates if the value is negative
	NegativeSign position.Position  // optional -
	Raw          ByteSliceReference // e.g. 13.37
}

func (d *Document) FloatValueAsFloat32(ref int) (out float32) {
	in := d.Input.ByteSlice(d.FloatValues[ref].Raw)
	out = unsafebytes.BytesToFloat32(in)
	if d.FloatValues[ref].Negative {
		out = -out
	}
	return
}

// EnumValue
// example:
// Name but not true or false or null
type EnumValue struct {
	Name ByteSliceReference // e.g. ORIGIN
}

// BooleanValues
// one of: true, false
type BooleanValue bool

// ObjectValue
// example:
// { lon: 12.43, lat: -53.211 }
type ObjectValue struct {
	LBRACE position.Position
	Refs   []int // ObjectField
	RBRACE position.Position
}

// ObjectField
// example:
// lon: 12.43
type ObjectField struct {
	Name  ByteSliceReference // e.g. lon
	Colon position.Position  // :
	Value Value              // e.g. 12.43
}

type Description struct {
	IsDefined     bool
	IsBlockString bool               // true if -> """content""" ; else "content"
	Content       ByteSliceReference // literal
	Position      position.Position
}

// nolint
func (d *Document) PrintDescription(description Description, indent []byte, depth int, writer io.Writer) (err error) {
	for i := 0; i < depth; i++ {
		_, err = writer.Write(indent)
	}
	if description.IsBlockString {
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.LINETERMINATOR)
		for i := 0; i < depth; i++ {
			_, err = writer.Write(indent)
		}
	} else {
		_, err = writer.Write(literal.QUOTE)
	}

	content := d.Input.ByteSlice(description.Content)
	skipWhitespace := false
	for i := range content {
		switch content[i] {
		case runes.LINETERMINATOR:
			skipWhitespace = true
		case runes.TAB, runes.SPACE:
			if skipWhitespace {
				continue
			}
		default:
			if skipWhitespace {
				for i := 0; i < depth; i++ {
					_, err = writer.Write(indent)
				}
			}
			skipWhitespace = false
		}
		_, err = writer.Write(content[i : i+1])
	}
	if description.IsBlockString {
		_, err = writer.Write(literal.LINETERMINATOR)
		for i := 0; i < depth; i++ {
			_, err = writer.Write(indent)
		}
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
	} else {
		_, err = writer.Write(literal.QUOTE)
	}
	return nil
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

type TypeList struct {
	Refs []int // Type
}

type FieldDefinitionList struct {
	LBRACE position.Position // {
	Refs   []int             // FieldDefinition
	RBRACE position.Position // }
}

type ObjectTypeExtension struct {
	ExtendLiteral position.Position
	ObjectTypeDefinition
}

func (d *Document) ObjectTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ObjectTypeExtensions[ref].Name)
}

func (d *Document) ObjectTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ObjectTypeExtensions[ref].Name))
}

func (d *Document) ObjectTypeExtensionHasFieldDefinitions(ref int) bool {
	return d.ObjectTypeExtensions[ref].HasFieldDefinitions
}

func (d *Document) ObjectTypeExtensionHasDirectives(ref int) bool {
	return d.ObjectTypeExtensions[ref].HasDirectives
}

type InputValueDefinition struct {
	Description   Description        // optional, e.g. "input Foo is..."
	Name          ByteSliceReference // e.g. Foo
	Colon         position.Position  // :
	Type          int                // e.g. String
	DefaultValue  DefaultValue       // e.g. = "Bar"
	HasDirectives bool
	Directives    DirectiveList // e.g. @baz
}

func (d *Document) InputValueDefinitionHasDefaultValue(ref int) bool {
	return d.InputValueDefinitions[ref].DefaultValue.IsDefined
}

func (d *Document) InputValueDefinitionDefaultValue(ref int) Value {
	return d.InputValueDefinitions[ref].DefaultValue.Value
}

func (d *Document) InputValueDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InputValueDefinitions[ref].Name)
}

func (d *Document) InputValueDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InputValueDefinitions[ref].Name))
}

func (d *Document) InputValueDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.InputValueDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InputValueDefinitions[ref].Description.Content)
}

func (d *Document) InputValueDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InputValueDefinitionDescriptionBytes(ref))
}

func (d *Document) InputValueDefinitionType(ref int) int {
	return d.InputValueDefinitions[ref].Type
}

func (d *Document) NodeInputValueDefinitions(node Node) []int {
	switch node.Kind {
	case NodeKindInputObjectTypeDefinition:
		return d.InputObjectTypeDefinitions[node.Ref].InputFieldsDefinition.Refs
	case NodeKindInputObjectTypeExtension:
		return d.InputObjectTypeExtensions[node.Ref].InputFieldsDefinition.Refs
	case NodeKindFieldDefinition:
		return d.FieldDefinitions[node.Ref].ArgumentsDefinition.Refs
	case NodeKindDirectiveDefinition:
		return d.DirectiveDefinitions[node.Ref].ArgumentsDefinition.Refs
	default:
		return nil
	}
}

func (d *Document) InputValueDefinitionIsFirst(inputValue int, ancestor Node) bool {
	inputValues := d.NodeInputValueDefinitions(ancestor)
	return inputValues != nil && inputValues[0] == inputValue
}

func (d *Document) InputValueDefinitionIsLast(inputValue int, ancestor Node) bool {
	inputValues := d.NodeInputValueDefinitions(ancestor)
	return inputValues != nil && inputValues[len(inputValues)-1] == inputValue
}

func (d *Document) InputValueDefinitionArgumentIsOptional(ref int) bool {
	nonNull := d.Types[d.InputValueDefinitions[ref].Type].TypeKind == TypeKindNonNull
	hasDefault := d.InputValueDefinitions[ref].DefaultValue.IsDefined
	return !nonNull || hasDefault
}

func (d *Document) InputValueDefinitionHasDirective(ref int, directiveName ByteSlice) bool {
	if !d.InputValueDefinitions[ref].HasDirectives {
		return false
	}
	for _, i := range d.InputValueDefinitions[ref].Directives.Refs {
		if bytes.Equal(directiveName, d.DirectiveNameBytes(i)) {
			return true
		}
	}
	return false
}

func (d *Document) AddInputValueDefinition(inputValueDefinition InputValueDefinition) (ref int) {
	d.InputValueDefinitions = append(d.InputValueDefinitions, inputValueDefinition)
	return len(d.InputValueDefinitions) - 1
}

type Type struct {
	TypeKind TypeKind           // one of Named,List,NonNull
	Name     ByteSliceReference // e.g. String (only on NamedType)
	Open     position.Position  // [ (only on ListType)
	Close    position.Position  // ] (only on ListType)
	Bang     position.Position  // ! (only on NonNullType)
	OfType   int
}

func (d *Document) TypeNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Types[ref].Name)
}

func (d *Document) TypeNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.Types[ref].Name))
}

func (d *Document) PrintType(ref int, w io.Writer) error {
	switch d.Types[ref].TypeKind {
	case TypeKindNonNull:
		err := d.PrintType(d.Types[ref].OfType, w)
		if err != nil {
			return err
		}
		_, err = w.Write(literal.BANG)
		return err
	case TypeKindNamed:
		_, err := w.Write(d.Input.ByteSlice(d.Types[ref].Name))
		return err
	case TypeKindList:
		_, err := w.Write(literal.LBRACK)
		if err != nil {
			return err
		}
		err = d.PrintType(d.Types[ref].OfType, w)
		if err != nil {
			return err
		}
		_, err = w.Write(literal.RBRACK)
		return err
	}
	return nil
}

func (d *Document) PrintTypeBytes(ref int, buf []byte) ([]byte, error) {
	if buf == nil {
		buf = make([]byte, 0, 24)
	}
	b := bytes.NewBuffer(buf)
	err := d.PrintType(ref, b)
	return b.Bytes(), err
}

func (d *Document) AddNamedType(name []byte) (ref int) {
	nameRef := d.Input.AppendInputBytes(name)
	d.Types = append(d.Types, Type{
		TypeKind: TypeKindNamed,
		Name:     nameRef,
	})
	return len(d.Types) - 1
}

func (d *Document) AddNonNullNamedType(name []byte) (ref int) {
	namedRef := d.AddNamedType(name)
	d.Types = append(d.Types, Type{
		TypeKind: TypeKindNonNull,
		OfType:   namedRef,
	})
	return len(d.Types) - 1
}

type DefaultValue struct {
	IsDefined bool
	Equals    position.Position // =
	Value     Value             // e.g. "Foo"
}

type InputObjectTypeDefinition struct {
	Description              Description        // optional, describes the input type
	InputLiteral             position.Position  // input
	Name                     ByteSliceReference // name of the input type
	HasDirectives            bool
	Directives               DirectiveList // optional, e.g. @foo
	HasInputFieldsDefinition bool
	InputFieldsDefinition    InputValueDefinitionList // e.g. x:Float
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueString(inputObjectTypeDefinitionName, inputValueDefinitionName string) string {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindString {
		return ""
	}
	return d.StringValueContentString(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueBool(inputObjectTypeDefinitionName, inputValueDefinitionName string) bool {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindBoolean {
		return false
	}
	return bool(d.BooleanValue(defaultValue.Ref))
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueInt64(inputObjectTypeDefinitionName, inputValueDefinitionName string) int64 {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindInteger {
		return -1
	}
	return d.IntValueAsInt(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueFloat32(inputObjectTypeDefinitionName, inputValueDefinitionName string) float32 {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindFloat {
		return -1
	}
	return d.FloatValueAsFloat32(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName string) Value {
	inputObjectTypeDefinition := d.Index.Nodes[xxhash.Sum64String(inputObjectTypeDefinitionName)]
	if inputObjectTypeDefinition.Kind != NodeKindInputObjectTypeDefinition {
		return Value{}
	}
	inputValueDefinition := d.InputObjectTypeDefinitionInputValueDefinitionByName(inputObjectTypeDefinition.Ref, unsafebytes.StringToBytes(inputValueDefinitionName))
	if inputValueDefinition == -1 {
		return Value{}
	}
	return d.InputValueDefinitionDefaultValue(inputValueDefinition)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionByName(definition int, inputValueDefinitionName ByteSlice) int {
	for _, i := range d.InputObjectTypeDefinitions[definition].InputFieldsDefinition.Refs {
		if bytes.Equal(inputValueDefinitionName, d.InputValueDefinitionNameBytes(i)) {
			return i
		}
	}
	return -1
}

func (d *Document) InputObjectTypeExtensionHasDirectives(ref int) bool {
	return d.InputObjectTypeExtensions[ref].HasDirectives
}

func (d *Document) InputObjectTypeExtensionHasInputFieldsDefinition(ref int) bool {
	return d.InputObjectTypeDefinitions[ref].HasInputFieldsDefinition
}

func (d *Document) InputObjectTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Name)
}

func (d *Document) InputObjectTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Name))
}

func (d *Document) InputObjectTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.InputObjectTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Description.Content)
}

func (d *Document) InputObjectTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InputObjectTypeDefinitionNameBytes(ref))
}

type InputObjectTypeExtension struct {
	ExtendLiteral position.Position
	InputObjectTypeDefinition
}

func (d *Document) InputObjectTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InputObjectTypeExtensions[ref].Name)
}

func (d *Document) InputObjectTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InputObjectTypeExtensions[ref].Name))
}

// ScalarTypeDefinition
// example:
// scalar JSON
type ScalarTypeDefinition struct {
	Description   Description        // optional, describes the scalar
	ScalarLiteral position.Position  // scalar
	Name          ByteSliceReference // e.g. JSON
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

func (d *Document) ScalarTypeDefinitionHasDirectives(ref int) bool {
	return d.ScalarTypeDefinitions[ref].HasDirectives
}

func (d *Document) ScalarTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ScalarTypeDefinitions[ref].Name)
}

func (d *Document) ScalarTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ScalarTypeDefinitions[ref].Name))
}

type ScalarTypeExtension struct {
	ExtendLiteral position.Position
	ScalarTypeDefinition
}

func (d *Document) ScalarTypeExtensionHasDirectives(ref int) bool {
	return d.ScalarTypeExtensions[ref].HasDirectives
}

func (d *Document) ScalarTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ScalarTypeExtensions[ref].Name)
}

func (d *Document) ScalarTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.ScalarTypeExtensions[ref].Name))
}

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

func (d *Document) InterfaceTypeExtensionHasDirectives(ref int) bool {
	return d.InterfaceTypeExtensions[ref].HasDirectives
}

func (d *Document) InterfaceTypeExtensionHasFieldDefinitions(ref int) bool {
	return d.InterfaceTypeExtensions[ref].HasFieldDefinitions
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

type InterfaceTypeExtension struct {
	ExtendLiteral position.Position
	InterfaceTypeDefinition
}

func (d *Document) InterfaceTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InterfaceTypeExtensions[ref].Name)
}

func (d *Document) InterfaceTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InterfaceTypeExtensions[ref].Name))
}

// UnionTypeDefinition
// example:
// union SearchResult = Photo | Person
type UnionTypeDefinition struct {
	Description         Description        // optional, describes union
	UnionLiteral        position.Position  // union
	Name                ByteSliceReference // e.g. SearchResult
	HasDirectives       bool
	Directives          DirectiveList     // optional, e.g. @foo
	Equals              position.Position // =
	HasUnionMemberTypes bool
	UnionMemberTypes    TypeList // optional, e.g. Photo | Person
}

func (d *Document) UnionMemberTypeIsFirst(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindUnionTypeDefinition:
		return len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs[0] == ref
	case NodeKindUnionTypeExtension:
		return len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs[0] == ref
	default:
		return false
	}
}

func (d *Document) UnionMemberTypeIsLast(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindUnionTypeDefinition:
		return len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs[len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs)-1] == ref
	case NodeKindUnionTypeExtension:
		return len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs[len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs)-1] == ref
	default:
		return false
	}
}

func (d *Document) UnionTypeDefinitionHasDirectives(ref int) bool {
	return d.UnionTypeDefinitions[ref].HasDirectives
}

func (d *Document) UnionTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Name)
}

func (d *Document) UnionTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Name))
}

func (d *Document) UnionTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.UnionTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Description.Content)
}

func (d *Document) UnionTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.UnionTypeDefinitionDescriptionBytes(ref))
}

type UnionTypeExtension struct {
	ExtendLiteral position.Position
	UnionTypeDefinition
}

func (d *Document) UnionTypeExtensionHasDirectives(ref int) bool {
	return d.UnionTypeExtensions[ref].HasDirectives
}

func (d *Document) UnionTypeExtensionHasUnionMemberTypes(ref int) bool {
	return d.UnionTypeExtensions[ref].HasUnionMemberTypes
}

func (d *Document) UnionTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.UnionTypeExtensions[ref].Name)
}

func (d *Document) UnionTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.UnionTypeExtensions[ref].Name))
}

// EnumTypeDefinition
// example:
// enum Direction {
//  NORTH
//  EAST
//  SOUTH
//  WEST
//}
type EnumTypeDefinition struct {
	Description             Description        // optional, describes enum
	EnumLiteral             position.Position  // enum
	Name                    ByteSliceReference // e.g. Direction
	HasDirectives           bool
	Directives              DirectiveList // optional, e.g. @foo
	HasEnumValuesDefinition bool
	EnumValuesDefinition    EnumValueDefinitionList // optional, e.g. { NORTH EAST }
}

func (d *Document) EnumTypeDefinitionHasDirectives(ref int) bool {
	return d.EnumTypeDefinitions[ref].HasDirectives
}

func (d *Document) EnumTypeDefinitionHasEnumValueDefinition(ref int) bool {
	return d.EnumTypeDefinitions[ref].HasEnumValuesDefinition
}

func (d *Document) EnumTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Name)
}

func (d *Document) EnumTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Name))
}

func (d *Document) EnumTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.EnumTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Description.Content)
}

func (d *Document) EnumTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.EnumTypeDefinitionDescriptionBytes(ref))
}

func (d *Document) EnumTypeDefinitionContainsEnumValue(enumTypeDef int, valueName ByteSlice) bool {
	for _, i := range d.EnumTypeDefinitions[enumTypeDef].EnumValuesDefinition.Refs {
		if bytes.Equal(valueName, d.EnumValueDefinitionNameBytes(i)) {
			return true
		}
	}
	return false
}

type EnumValueDefinitionList struct {
	LBRACE position.Position // {
	Refs   []int             //
	RBRACE position.Position // }
}

type EnumTypeExtension struct {
	ExtendLiteral position.Position
	EnumTypeDefinition
}

func (d *Document) EnumTypeExtensionHasDirectives(ref int) bool {
	return d.EnumTypeExtensions[ref].HasDirectives
}

func (d *Document) EnumTypeExtensionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumTypeExtensions[ref].Name)
}

func (d *Document) EnumTypeExtensionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumTypeExtensions[ref].Name))
}

// EnumValueDefinition
// example:
// "NORTH enum value" NORTH @foo
type EnumValueDefinition struct {
	Description   Description        // optional, describes enum value
	EnumValue     ByteSliceReference // e.g. NORTH (Name but not true, false or null
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

func (d *Document) EnumValueDefinitionIsFirst(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindEnumTypeDefinition:
		return d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs[0] == ref
	case NodeKindEnumTypeExtension:
		return d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs[0] == ref
	default:
		return false
	}
}

func (d *Document) EnumValueDefinitionIsLast(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindEnumTypeDefinition:
		return d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs[len(d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs)-1] == ref
	case NodeKindEnumTypeExtension:
		return d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs[len(d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs)-1] == ref
	default:
		return false
	}
}

func (d *Document) EnumValueDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumValueDefinitions[ref].EnumValue)
}

func (d *Document) EnumValueDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumValueDefinitions[ref].EnumValue))
}

func (d *Document) EnumValueDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.EnumValueDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.EnumValueDefinitions[ref].Description.Content)
}

func (d *Document) EnumValueDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.EnumValueDefinitionDescriptionBytes(ref))
}

// DirectiveDefinition
// example:
// directive @example on FIELD
type DirectiveDefinition struct {
	Description             Description        // optional, describes the directive
	DirectiveLiteral        position.Position  // directive
	At                      position.Position  // @
	Name                    ByteSliceReference // e.g. example
	HasArgumentsDefinitions bool
	ArgumentsDefinition     InputValueDefinitionList // optional, e.g. (if: Boolean)
	On                      position.Position        // on
	DirectiveLocations      DirectiveLocations       // e.g. FIELD
}

func (d *Document) DirectiveDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.DirectiveDefinitions[ref].Name)
}

func (d *Document) DirectiveDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.DirectiveDefinitions[ref].Name))
}

func (d *Document) DirectiveDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.DirectiveDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.DirectiveDefinitions[ref].Description.Content)
}

func (d *Document) DirectiveDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.DirectiveDefinitionDescriptionBytes(ref))
}

func (d *Document) RemoveDirectiveFromNode(node Node, ref int) {
	switch node.Kind {
	case NodeKindFragmentSpread:
		if i, ok := d.IndexOf(d.FragmentSpreads[node.Ref].Directives.Refs, ref); ok {
			d.FragmentSpreads[node.Ref].Directives.Refs = append(d.FragmentSpreads[node.Ref].Directives.Refs[:i], d.FragmentSpreads[node.Ref].Directives.Refs[i+1:]...)
			d.FragmentSpreads[node.Ref].HasDirectives = len(d.FragmentSpreads[node.Ref].Directives.Refs) > 0
		}
	case NodeKindInlineFragment:
		if i, ok := d.IndexOf(d.InlineFragments[node.Ref].Directives.Refs, ref); ok {
			d.InlineFragments[node.Ref].Directives.Refs = append(d.InlineFragments[node.Ref].Directives.Refs[:i], d.InlineFragments[node.Ref].Directives.Refs[i+1:]...)
			d.InlineFragments[node.Ref].HasDirectives = len(d.InlineFragments[node.Ref].Directives.Refs) > 0
		}
	case NodeKindField:
		if i, ok := d.IndexOf(d.Fields[node.Ref].Directives.Refs, ref); ok {
			d.Fields[node.Ref].Directives.Refs = append(d.Fields[node.Ref].Directives.Refs[:i], d.Fields[node.Ref].Directives.Refs[i+1:]...)
			d.Fields[node.Ref].HasDirectives = len(d.Fields[node.Ref].Directives.Refs) > 0
		}
	default:
		log.Printf("RemoveDirectiveFromNode not implemented for node kind: %s", node.Kind)
	}
}

func (d *Document) NodeDirectiveLocation(node Node) (location DirectiveLocation, err error) {
	switch node.Kind {
	case NodeKindSchemaDefinition:
		location = TypeSystemDirectiveLocationSchema
	case NodeKindSchemaExtension:
		location = TypeSystemDirectiveLocationSchema
	case NodeKindObjectTypeDefinition:
		location = TypeSystemDirectiveLocationObject
	case NodeKindObjectTypeExtension:
		location = TypeSystemDirectiveLocationObject
	case NodeKindInterfaceTypeDefinition:
		location = TypeSystemDirectiveLocationInterface
	case NodeKindInterfaceTypeExtension:
		location = TypeSystemDirectiveLocationInterface
	case NodeKindUnionTypeDefinition:
		location = TypeSystemDirectiveLocationUnion
	case NodeKindUnionTypeExtension:
		location = TypeSystemDirectiveLocationUnion
	case NodeKindEnumTypeDefinition:
		location = TypeSystemDirectiveLocationEnum
	case NodeKindEnumTypeExtension:
		location = TypeSystemDirectiveLocationEnum
	case NodeKindInputObjectTypeDefinition:
		location = TypeSystemDirectiveLocationInputObject
	case NodeKindInputObjectTypeExtension:
		location = TypeSystemDirectiveLocationInputObject
	case NodeKindScalarTypeDefinition:
		location = TypeSystemDirectiveLocationScalar
	case NodeKindOperationDefinition:
		switch d.OperationDefinitions[node.Ref].OperationType {
		case OperationTypeQuery:
			location = ExecutableDirectiveLocationQuery
		case OperationTypeMutation:
			location = ExecutableDirectiveLocationMutation
		case OperationTypeSubscription:
			location = ExecutableDirectiveLocationSubscription
		}
	case NodeKindField:
		location = ExecutableDirectiveLocationField
	case NodeKindFragmentSpread:
		location = ExecutableDirectiveLocationFragmentSpread
	case NodeKindInlineFragment:
		location = ExecutableDirectiveLocationInlineFragment
	case NodeKindFragmentDefinition:
		location = ExecutableDirectiveLocationFragmentDefinition
	case NodeKindVariableDefinition:
		location = ExecutableDirectiveLocationVariableDefinition
	default:
		err = fmt.Errorf("node kind: %s is not allowed to have directives", node.Kind)
	}
	return
}

func (d *Document) DirectiveLocationBytes(location DirectiveLocation) ByteSlice {
	switch location {
	case ExecutableDirectiveLocationQuery:
		return literal.LocationQuery
	case ExecutableDirectiveLocationMutation:
		return literal.LocationMutation
	case ExecutableDirectiveLocationSubscription:
		return literal.LocationSubscription
	case ExecutableDirectiveLocationField:
		return literal.LocationField
	case ExecutableDirectiveLocationFragmentDefinition:
		return literal.LocationFragmentDefinition
	case ExecutableDirectiveLocationFragmentSpread:
		return literal.LocationFragmentSpread
	case ExecutableDirectiveLocationInlineFragment:
		return literal.LocationInlineFragment
	case ExecutableDirectiveLocationVariableDefinition:
		return literal.LocationVariableDefinition
	case TypeSystemDirectiveLocationSchema:
		return literal.LocationSchema
	case TypeSystemDirectiveLocationScalar:
		return literal.LocationScalar
	case TypeSystemDirectiveLocationObject:
		return literal.LocationObject
	case TypeSystemDirectiveLocationFieldDefinition:
		return literal.LocationFieldDefinition
	case TypeSystemDirectiveLocationArgumentDefinition:
		return literal.LocationArgumentDefinition
	case TypeSystemDirectiveLocationInterface:
		return literal.LocationInterface
	case TypeSystemDirectiveLocationUnion:
		return literal.LocationUnion
	case TypeSystemDirectiveLocationEnum:
		return literal.LocationEnum
	case TypeSystemDirectiveLocationEnumValue:
		return literal.LocationEnumValue
	case TypeSystemDirectiveLocationInputObject:
		return literal.LocationInputObject
	case TypeSystemDirectiveLocationInputFieldDefinition:
		return literal.LocationInputFieldDefinition
	default:
		return nil
	}
}

func (d *Document) DirectiveLocationString(location DirectiveLocation) string {
	return unsafebytes.BytesToString(d.DirectiveLocationBytes(location))
}

type OperationDefinition struct {
	OperationType          OperationType      // one of query, mutation, subscription
	OperationTypeLiteral   position.Position  // position of the operation type literal, if present
	Name                   ByteSliceReference // optional, user defined name of the operation
	HasVariableDefinitions bool
	VariableDefinitions    VariableDefinitionList // optional, e.g. ($devicePicSize: Int)
	HasDirectives          bool
	Directives             DirectiveList // optional, e.g. @foo
	SelectionSet           int           // e.g. {field}
	HasSelections          bool
}

func (d *Document) OperationDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.OperationDefinitions[ref].Name)
}

func (d *Document) OperationDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.OperationDefinitions[ref].Name))
}

func (d *Document) OperationDefinitionIsLastRootNode(ref int) bool {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindOperationDefinition && d.RootNodes[i].Ref == ref {
			return len(d.RootNodes)-1 == i
		}
	}
	return false
}

func (d *Document) FragmentDefinitionIsLastRootNode(ref int) bool {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindFragmentDefinition && d.RootNodes[i].Ref == ref {
			return len(d.RootNodes)-1 == i
		}
	}
	return false
}

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

func (d *Document) VariableDefinitionsBefore(variableDefinition int) bool {
	return variableDefinition != 0
}

func (d *Document) VariableDefinitionsAfter(variableDefinition int) bool {
	return len(d.VariableDefinitions) != 1 && variableDefinition != len(d.VariableDefinitions)-1
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

func (d *Document) DirectiveArgumentInputValueDefinition(directiveName ByteSlice, argumentName ByteSlice) int {
	for i := range d.DirectiveDefinitions {
		if bytes.Equal(directiveName, d.Input.ByteSlice(d.DirectiveDefinitions[i].Name)) {
			for _, j := range d.DirectiveDefinitions[i].ArgumentsDefinition.Refs {
				if bytes.Equal(argumentName, d.Input.ByteSlice(d.InputValueDefinitions[j].Name)) {
					return j
				}
			}
		}
	}
	return -1
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueString(directiveName, argumentName string) string {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return ""
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindString {
		return ""
	}
	return d.StringValueContentString(defaultValue.Ref)
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueBool(directiveName, argumentName string) bool {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return false
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindBoolean {
		return false
	}
	return bool(d.BooleanValue(defaultValue.Ref))
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueInt64(directiveName, argumentName string) int64 {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return -1
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindInteger {
		return -1
	}
	return d.IntValueAsInt(defaultValue.Ref)
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueFloat32(directiveName, argumentName string) float32 {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return -1
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindFloat {
		return -1
	}
	return d.FloatValueAsFloat32(defaultValue.Ref)
}

type SelectionSet struct {
	LBrace        position.Position
	RBrace        position.Position
	SelectionRefs []int
}

type Selection struct {
	Kind SelectionKind // one of Field, FragmentSpread, InlineFragment
	Ref  int           // reference to the actual selection
}

func (d *Document) SelectionsBeforeField(field int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindField && d.Selections[j].Ref == field {
			return i != 0
		}
	}

	return false
}

func (d *Document) SelectionsAfterField(field int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindField && d.Selections[j].Ref == field {
			return i != len(d.SelectionSets[selectionSet.Ref].SelectionRefs)-1
		}
	}

	return false
}

func (d *Document) SelectionsAfterInlineFragment(inlineFragment int, selectionSet Node) bool {
	if selectionSet.Kind != NodeKindSelectionSet {
		return false
	}

	if len(d.SelectionSets[selectionSet.Ref].SelectionRefs) == 1 {
		return false
	}

	for i, j := range d.SelectionSets[selectionSet.Ref].SelectionRefs {
		if d.Selections[j].Kind == SelectionKindInlineFragment && d.Selections[j].Ref == inlineFragment {
			return i != len(d.SelectionSets[selectionSet.Ref].SelectionRefs)-1
		}
	}

	return false
}

type Field struct {
	Alias         Alias              // optional, e.g. renamed:
	Name          ByteSliceReference // field name, e.g. id
	HasArguments  bool
	Arguments     ArgumentList // optional
	HasDirectives bool
	Directives    DirectiveList // optional
	SelectionSet  int           // optional
	HasSelections bool
}

func (d *Document) FieldObjectNameString(ref int) string {
	return unsafebytes.BytesToString(d.FieldObjectNameBytes(ref))
}

func (d *Document) FieldObjectNameBytes(ref int) ByteSlice {
	if d.Fields[ref].Alias.IsDefined {
		return d.FieldAliasBytes(ref)
	}
	return d.FieldNameBytes(ref)
}

func (d *Document) FieldNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Fields[ref].Name)
}

func (d *Document) FieldNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.Fields[ref].Name))
}

type Alias struct {
	IsDefined bool
	Name      ByteSliceReference // optional, e.g. renamedField
	Colon     position.Position  // :
}

// FragmentSpread
// example:
// ...MyFragment
type FragmentSpread struct {
	Spread        position.Position  // ...
	FragmentName  ByteSliceReference // Name but not on, e.g. MyFragment
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

// InlineFragment
// example:
// ... on User {
//      friends {
//        count
//      }
//    }
type InlineFragment struct {
	Spread        position.Position // ...
	TypeCondition TypeCondition     // on NamedType, e.g. on User
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
	SelectionSet  int           // optional, e.g. { nextField }
	HasSelections bool
}

// TypeCondition
// example:
// on User
type TypeCondition struct {
	On   position.Position // on
	Type int               // NamedType
}

// FragmentDefinition
// example:
// fragment friendFields on User {
//  id
//  name
//  profilePic(size: 50)
//}
type FragmentDefinition struct {
	FragmentLiteral position.Position  // fragment
	Name            ByteSliceReference // Name but not on, e.g. friendFields
	TypeCondition   TypeCondition      // e.g. on User
	Directives      DirectiveList      // optional, e.g. @foo
	SelectionSet    int                // e.g. { id }
	HasSelections   bool
}

func (d *Document) FragmentDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FragmentDefinitions[ref].Name)
}

func (d *Document) FragmentDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.FragmentDefinitions[ref].Name))
}

type PathKind int

const (
	UnknownPathKind PathKind = iota
	ArrayIndex
	FieldName
)

type PathItem struct {
	Kind       PathKind
	ArrayIndex int
	FieldName  ByteSlice
}

type Path []PathItem

func (p Path) Equals(another Path) bool {
	if len(p) != len(another) {
		return false
	}
	for i := range p {
		if p[i].Kind != another[i].Kind {
			return false
		}
		if p[i].Kind == ArrayIndex && p[i].ArrayIndex != another[i].ArrayIndex {
			return false
		} else if !bytes.Equal(p[i].FieldName, another[i].FieldName) {
			return false
		}
	}
	return true
}

func (p Path) String() string {
	out := "["
	for i := range p {
		if i != 0 {
			out += ","
		}
		switch p[i].Kind {
		case ArrayIndex:
			out += strconv.Itoa(p[i].ArrayIndex)
		case FieldName:
			if len(p[i].FieldName) == 0 {
				out += "query"
			} else {
				out += unsafebytes.BytesToString(p[i].FieldName)
			}
		}
	}
	out += "]"
	return out
}

func (p Path) DotDelimitedString() string {
	out := ""
	for i := range p {
		if i != 0 {
			out += "."
		}
		switch p[i].Kind {
		case ArrayIndex:
			out += strconv.Itoa(p[i].ArrayIndex)
		case FieldName:
			if len(p[i].FieldName) == 0 {
				out += "query"
			} else {
				out += unsafebytes.BytesToString(p[i].FieldName)
			}
		}
	}
	return out
}

func (p *PathItem) UnmarshalJSON(data []byte) error {
	if data == nil {
		return fmt.Errorf("data must not be nil")
	}
	if data[0] == '"' && data[len(data)-1] == '"' {
		p.Kind = FieldName
		p.FieldName = data[1 : len(data)-1]
		return nil
	}
	out, err := strconv.ParseInt(*(*string)(unsafe.Pointer(&data)), 10, 64)
	if err != nil {
		return err
	}
	p.Kind = ArrayIndex
	p.ArrayIndex = int(out)
	return nil
}

func (p PathItem) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case ArrayIndex:
		return strconv.AppendInt(nil, int64(p.ArrayIndex), 10), nil
	case FieldName:
		return append([]byte("\""), append(p.FieldName, []byte("\"")...)...), nil
	default:
		return nil, fmt.Errorf("cannot marshal unknown PathKind")
	}
}

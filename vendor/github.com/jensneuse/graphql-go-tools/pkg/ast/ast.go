//go:generate stringer -type=OperationType,ValueKind,TypeKind,SelectionKind,NodeKind,PathKind -output ast_string.go

// Package ast defines the GraphQL AST and offers helper methods to interact with the AST, mostly to get the necessary information from the ast.
//
// The document struct is designed in a way to enable performant parsing while keeping the ast easy to use with helper methods.
package ast

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
			nodes: make(map[uint64][]Node, 48),
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
	d.Input.Reset()
}

func (d *Document) NextRefIndex() int {
	d.RefIndex++
	if d.RefIndex == len(d.Refs) {
		d.Refs = append(d.Refs, [8]int{})
	}
	return d.RefIndex
}

func (d *Document) AddRootNode(node Node) {
	d.RootNodes = append(d.RootNodes, node)
	d.Index.AddNodeStr(d.NodeNameString(node), node)
}

func (d *Document) ImportRootNode(ref int, kind NodeKind) {
	d.AddRootNode(Node{
		Kind: kind,
		Ref:  ref,
	})
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

func (d *Document) NodeByName(name ByteSlice) (Node, bool) {
	node, exists := d.Index.FirstNodeByNameBytes(name)
	return node, exists
}

func (d *Document) TypeDefinitionContainsImplementsInterface(typeName, interfaceName ByteSlice) bool {
	typeDefinition, exists := d.Index.FirstNodeByNameBytes(typeName)
	if !exists {
		return false
	}
	if typeDefinition.Kind != NodeKindObjectTypeDefinition {
		return false
	}
	return d.ObjectTypeDefinitionImplementsInterface(typeDefinition.Ref, interfaceName)
}

func FilterIntSliceByWhitelist(intSlice []int, whitelist []int) []int {
	if len(intSlice) == 0 || len(whitelist) == 0 {
		return []int{}
	}
	n := 0
	for i := 0; i < len(intSlice); i++ {
		if isWhitelisted(intSlice[i], whitelist) {
			intSlice[n] = intSlice[i]
			n++
		}
	}
	return intSlice[:n]
}

func isWhitelisted(value int, whitelisted []int) bool {
	for i := 0; i < len(whitelisted); i++ {
		if whitelisted[i] == value {
			return true
		}
	}
	return false
}

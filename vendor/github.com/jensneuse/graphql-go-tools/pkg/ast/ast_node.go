package ast

import (
	"bytes"
	"fmt"
	"log"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
)

type Node struct {
	Kind NodeKind
	Ref  int
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

func (n Node) NameBytes(definition *Document) []byte {
	return definition.NodeNameBytes(n)
}

func (n Node) NameString(definition *Document) string {
	return unsafebytes.BytesToString(definition.NodeNameBytes(n))
}

// TODO: we could use node name directly
func (d *Document) NodeNameString(node Node) string {
	return unsafebytes.BytesToString(d.NodeNameBytes(node))
}

// Node directives

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
	case NodeKindFieldDefinition:
		return d.FieldDefinitions[node.Ref].Directives.Refs
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

// Node resolvers

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

// Node field definitions

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

// Node input value definitions

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

// Node misc

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

func (d *Document) NodeIsUnionMember(node Node, union Node) bool {
	nodeTypeName := d.NodeNameBytes(node)
	for _, i := range d.UnionTypeDefinitions[union.Ref].UnionMemberTypes.Refs {
		memberName := d.ResolveTypeNameBytes(i)
		if bytes.Equal(nodeTypeName, memberName) {
			return true
		}
	}
	return false
}

func (d *Document) NodeIsLastRootNode(node Node) bool {
	if len(d.RootNodes) == 0 {
		return false
	}
	for i := len(d.RootNodes) - 1; i >= 0; i-- {
		if d.RootNodes[i].Kind == NodeKindUnknown {
			continue
		}
		return d.RootNodes[i] == node
	}
	return false
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

// Node fragments

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
		memberName := d.ResolveTypeNameBytes(i)
		node, exists := d.Index.FirstNodeByNameBytes(memberName)
		if !exists {
			continue
		}
		if node.Kind != NodeKindObjectTypeDefinition {
			continue
		}
		if d.NodeImplementsInterface(node, interfaceNode) {
			return true
		}
	}
	return false
}

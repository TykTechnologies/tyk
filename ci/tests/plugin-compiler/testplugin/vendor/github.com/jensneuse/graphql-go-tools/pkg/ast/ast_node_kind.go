package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type NodeKind int

const (
	NodeKindUnknown NodeKind = 22 + iota
	NodeKindSchemaDefinition
	NodeKindSchemaExtension
	NodeKindObjectTypeDefinition
	NodeKindObjectTypeExtension
	NodeKindInterfaceTypeDefinition
	NodeKindInterfaceTypeExtension
	NodeKindUnionTypeDefinition
	NodeKindUnionTypeExtension
	NodeKindUnionMemberType
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

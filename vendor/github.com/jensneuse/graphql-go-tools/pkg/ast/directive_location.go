//go:generate stringer -type=DirectiveLocation -output directive_location_string.go

package ast

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type DirectiveLocation int

const (
	DirectiveLocationUnknown DirectiveLocation = iota
	ExecutableDirectiveLocationQuery
	ExecutableDirectiveLocationMutation
	ExecutableDirectiveLocationSubscription
	ExecutableDirectiveLocationField
	ExecutableDirectiveLocationFragmentDefinition
	ExecutableDirectiveLocationFragmentSpread
	ExecutableDirectiveLocationInlineFragment
	ExecutableDirectiveLocationVariableDefinition

	TypeSystemDirectiveLocationSchema
	TypeSystemDirectiveLocationScalar
	TypeSystemDirectiveLocationObject
	TypeSystemDirectiveLocationFieldDefinition
	TypeSystemDirectiveLocationArgumentDefinition
	TypeSystemDirectiveLocationInterface
	TypeSystemDirectiveLocationUnion
	TypeSystemDirectiveLocationEnum
	TypeSystemDirectiveLocationEnumValue
	TypeSystemDirectiveLocationInputObject
	TypeSystemDirectiveLocationInputFieldDefinition
)

var (
	locations = map[string]DirectiveLocation{
		"QUERY":                  ExecutableDirectiveLocationQuery,
		"MUTATION":               ExecutableDirectiveLocationMutation,
		"SUBSCRIPTION":           ExecutableDirectiveLocationSubscription,
		"FIELD":                  ExecutableDirectiveLocationField,
		"FRAGMENT_DEFINITION":    ExecutableDirectiveLocationFragmentDefinition,
		"FRAGMENT_SPREAD":        ExecutableDirectiveLocationFragmentSpread,
		"INLINE_FRAGMENT":        ExecutableDirectiveLocationInlineFragment,
		"VARIABLE_DEFINITION":    ExecutableDirectiveLocationVariableDefinition,
		"SCHEMA":                 TypeSystemDirectiveLocationSchema,
		"SCALAR":                 TypeSystemDirectiveLocationScalar,
		"OBJECT":                 TypeSystemDirectiveLocationObject,
		"FIELD_DEFINITION":       TypeSystemDirectiveLocationFieldDefinition,
		"ARGUMENT_DEFINITION":    TypeSystemDirectiveLocationArgumentDefinition,
		"INTERFACE":              TypeSystemDirectiveLocationInterface,
		"UNION":                  TypeSystemDirectiveLocationUnion,
		"ENUM":                   TypeSystemDirectiveLocationEnum,
		"ENUM_VALUE":             TypeSystemDirectiveLocationEnumValue,
		"INPUT_OBJECT":           TypeSystemDirectiveLocationInputObject,
		"INPUT_FIELD_DEFINITION": TypeSystemDirectiveLocationInputFieldDefinition,
	}
)

type DirectiveLocations struct {
	storage [20]bool
}

func (d *DirectiveLocations) Get(location DirectiveLocation) bool {
	return d.storage[location]
}

func (d *DirectiveLocations) Set(location DirectiveLocation) {
	d.storage[location] = true
}

func (d *DirectiveLocations) Unset(location DirectiveLocation) {
	d.storage[location] = false
}

func (d *DirectiveLocations) Iterable() DirectiveLocationIterable {
	return DirectiveLocationIterable{
		locations: *d,
	}
}

func (d *DirectiveLocations) SetFromRaw(bytes []byte) error {

	location, exists := locations[string(bytes)]
	if !exists {
		return fmt.Errorf("invalid directive location: %s", string(bytes))
	}

	d.Set(location)

	return nil
}

type DirectiveLocationIterable struct {
	locations DirectiveLocations
	current   DirectiveLocation
}

func (d *DirectiveLocationIterable) Next() bool {
	for i := d.current + 1; i < 20; i++ {
		if d.locations.storage[i] {
			d.current = i
			return true
		}
	}
	return false
}

func (d *DirectiveLocationIterable) Value() DirectiveLocation {
	return d.current
}

func (d DirectiveLocation) LiteralBytes() ByteSlice {
	switch d {
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

func (d DirectiveLocation) LiteralString() string {
	return unsafebytes.BytesToString(d.LiteralBytes())
}

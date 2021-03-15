package asttransform

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func MergeDefinitionWithBaseSchema(definition *ast.Document) error {
	definition.Input.AppendInputBytes(baseSchema)
	parser := astparser.NewParser()
	report := operationreport.Report{}
	parser.Parse(definition, &report)
	if report.HasErrors() {
		return report
	}
	return handleSchema(definition)
}

func handleSchema(definition *ast.Document) error {
	if err := addSchemaDefinition(definition); err != nil {
		return err
	}

	queryNode, ok := findQueryNode(definition)
	if !ok {
		return nil
	}

	if err := addIntrospectionQueryFields(definition, queryNode.Ref); err != nil {
		return err
	}

	return nil
}

func addSchemaDefinition(definition *ast.Document) error {
	if definition.HasSchemaDefinition() {
		return nil
	}

	schemaDefinition := ast.SchemaDefinition{}
	var rootOperationTypeRefs []int

	for i := range definition.RootNodes {
		if definition.RootNodes[i].Kind == ast.NodeKindObjectTypeDefinition {
			typeName := definition.ObjectTypeDefinitionNameBytes(definition.RootNodes[i].Ref)

			switch {
			case bytes.Equal(typeName, []byte("Query")):
				ref := definition.CreateRootOperationTypeDefinition(ast.OperationTypeQuery, i)
				rootOperationTypeRefs = append(rootOperationTypeRefs, ref)
			case bytes.Equal(typeName, []byte("Mutation")):
				ref := definition.CreateRootOperationTypeDefinition(ast.OperationTypeMutation, i)
				rootOperationTypeRefs = append(rootOperationTypeRefs, ref)
			case bytes.Equal(typeName, []byte("Subscription")):
				ref := definition.CreateRootOperationTypeDefinition(ast.OperationTypeSubscription, i)
				rootOperationTypeRefs = append(rootOperationTypeRefs, ref)
			default:
				continue
			}
		}
	}

	schemaDefinition.AddRootOperationTypeDefinitionRefs(rootOperationTypeRefs...)
	definition.AddSchemaDefinitionRootNode(schemaDefinition)
	return nil
}

func addIntrospectionQueryFields(definition *ast.Document, objectTypeDefinitionRef int) error {
	var fieldRefs []int
	if !definition.ObjectTypeDefinitionHasField(objectTypeDefinitionRef, []byte("__schema")) {
		fieldRefs = append(fieldRefs, addSchemaField(definition))
	}

	if !definition.ObjectTypeDefinitionHasField(objectTypeDefinitionRef, []byte("__type")) {
		fieldRefs = append(fieldRefs, addTypeField(definition))
	}

	definition.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs = append(definition.ObjectTypeDefinitions[objectTypeDefinitionRef].FieldsDefinition.Refs, fieldRefs...)
	return nil
}

func addSchemaField(definition *ast.Document) (ref int) {
	fieldNameRef := definition.Input.AppendInputBytes([]byte("__schema"))
	fieldTypeRef := definition.AddNonNullNamedType([]byte("__Schema"))

	return definition.AddFieldDefinition(ast.FieldDefinition{
		Name: fieldNameRef,
		Type: fieldTypeRef,
	})
}

func addTypeField(definition *ast.Document) (ref int) {
	fieldNameRef := definition.Input.AppendInputBytes([]byte("__type"))
	fieldTypeRef := definition.AddNamedType([]byte("__Type"))

	argumentNameRef := definition.Input.AppendInputBytes([]byte("name"))
	argumentTypeRef := definition.AddNonNullNamedType([]byte("String"))

	argumentRef := definition.AddInputValueDefinition(ast.InputValueDefinition{
		Name: argumentNameRef,
		Type: argumentTypeRef,
	})

	return definition.AddFieldDefinition(ast.FieldDefinition{
		Name: fieldNameRef,
		Type: fieldTypeRef,

		HasArgumentsDefinitions: true,
		ArgumentsDefinition: ast.InputValueDefinitionList{
			Refs: []int{argumentRef},
		},
	})
}

func findQueryNode(definition *ast.Document) (queryNode ast.Node, ok bool) {
	queryNode, ok = definition.Index.FirstNodeByNameBytes(definition.Index.QueryTypeName)
	return queryNode, ok
}

var baseSchema = []byte(`"The 'Int' scalar type represents non-fractional signed whole numeric values. Int can represent values between -(2^31) and 2^31 - 1."
scalar Int
"The 'Float' scalar type represents signed double-precision fractional values as specified by [IEEE 754](http://en.wikipedia.org/wiki/IEEE_floating_point)."
scalar Float
"The 'String' scalar type represents textual data, represented as UTF-8 character sequences. The String type is most often used by GraphQL to represent free-form human-readable text."
scalar String
"The 'Boolean' scalar type represents 'true' or 'false' ."
scalar Boolean
"The 'ID' scalar type represents a unique identifier, often used to refetch an object or as key for a cache. The ID type appears in a JSON response as a String; however, it is not intended to be human-readable. When expected as an input type, any string (such as '4') or integer (such as 4) input value will be accepted as an ID."
scalar ID
"Directs the executor to include this field or fragment only when the argument is true."
directive @include(
    " Included when true."
    if: Boolean!
) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
"Directs the executor to skip this field or fragment when the argument is true."
directive @skip(
    "Skipped when true."
    if: Boolean!
) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
"Marks an element of a GraphQL schema as no longer supported."
directive @deprecated(
    """
    Explains why this element was deprecated, usually also including a suggestion
    for how to access supported similar data. Formatted in
    [Markdown](https://daringfireball.net/projects/markdown/).
    """
    reason: String = "No longer supported"
) on FIELD_DEFINITION | ENUM_VALUE

"""
A Directive provides a way to describe alternate runtime execution and type validation behavior in a GraphQL document.
In some cases, you need to provide options to alter GraphQL's execution behavior
in ways field arguments will not suffice, such as conditionally including or
skipping a field. Directives provide this by describing additional information
to the executor.
"""
type __Directive {
    name: String!
    description: String
    locations: [__DirectiveLocation!]!
    args: [__InputValue!]!
}

"""
A Directive can be adjacent to many parts of the GraphQL language, a
__DirectiveLocation describes one such possible adjacencies.
"""
enum __DirectiveLocation {
    "Location adjacent to a query operation."
    QUERY
    "Location adjacent to a mutation operation."
    MUTATION
    "Location adjacent to a subscription operation."
    SUBSCRIPTION
    "Location adjacent to a field."
    FIELD
    "Location adjacent to a fragment definition."
    FRAGMENT_DEFINITION
    "Location adjacent to a fragment spread."
    FRAGMENT_SPREAD
    "Location adjacent to an inline fragment."
    INLINE_FRAGMENT
    "Location adjacent to a schema definition."
    SCHEMA
    "Location adjacent to a scalar definition."
    SCALAR
    "Location adjacent to an object type definition."
    OBJECT
    "Location adjacent to a field definition."
    FIELD_DEFINITION
    "Location adjacent to an argument definition."
    ARGUMENT_DEFINITION
    "Location adjacent to an interface definition."
    INTERFACE
    "Location adjacent to a union definition."
    UNION
    "Location adjacent to an enum definition."
    ENUM
    "Location adjacent to an enum value definition."
    ENUM_VALUE
    "Location adjacent to an input object type definition."
    INPUT_OBJECT
    "Location adjacent to an input object field definition."
    INPUT_FIELD_DEFINITION
}
"""
One possible value for a given Enum. Enum values are unique values, not a
placeholder for a string or numeric value. However an Enum value is returned in
a JSON response as a string.
"""
type __EnumValue {
    name: String!
    description: String
    isDeprecated: Boolean!
    deprecationReason: String
}

"""
Object and Interface types are described by a list of Fields, each of which has
a name, potentially a list of arguments, and a return type.
"""
type __Field {
    name: String!
    description: String
    args: [__InputValue!]!
    type: __Type!
    isDeprecated: Boolean!
    deprecationReason: String
}

"""Arguments provided to Fields or Directives and the input fields of an
InputObject are represented as Input Values which describe their type and
optionally a default value.
"""
type __InputValue {
    name: String!
    description: String
    type: __Type!
    "A GraphQL-formatted string representing the default value for this input value."
    defaultValue: String
}

"""
A GraphQL Schema defines the capabilities of a GraphQL server. It exposes all
available types and directives on the server, as well as the entry points for
query, mutation, and subscription operations.
"""
type __Schema {
    "A list of all types supported by this server."
    types: [__Type!]!
    "The type that query operations will be rooted at."
    queryType: __Type!
    "If this server supports mutation, the type that mutation operations will be rooted at."
    mutationType: __Type
    "If this server support subscription, the type that subscription operations will be rooted at."
    subscriptionType: __Type
    "A list of all directives supported by this server."
    directives: [__Directive!]!
}

"""
The fundamental unit of any GraphQL Schema is the type. There are many kinds of
types in GraphQL as represented by the '__TypeKind' enum.

Depending on the kind of a type, certain fields describe information about that
type. Scalar types provide no information beyond a name and description, while
Enum types provide their values. Object and Interface types provide the fields
they describe. Abstract types, Union and Interface, provide the Object types
possible at runtime. List and NonNull types compose other types.
"""
type __Type {
    kind: __TypeKind!
    name: String
    description: String
    fields(includeDeprecated: Boolean = false): [__Field!]
    interfaces: [__Type!]
    possibleTypes: [__Type!]
    enumValues(includeDeprecated: Boolean = false): [__EnumValue!]
    inputFields: [__InputValue!]
    ofType: __Type
}

"An enum describing what kind of type a given '__Type' is."
enum __TypeKind {
    "Indicates this type is a scalar."
    SCALAR
    "Indicates this type is an object. 'fields' and 'interfaces' are valid fields."
    OBJECT
    "Indicates this type is an interface. 'fields' ' and ' 'possibleTypes' are valid fields."
    INTERFACE
    "Indicates this type is a union. 'possibleTypes' is a valid field."
    UNION
    "Indicates this type is an enum. 'enumValues' is a valid field."
    ENUM
    "Indicates this type is an input object. 'inputFields' is a valid field."
    INPUT_OBJECT
    "Indicates this type is a list. 'ofType' is a valid field."
    LIST
    "Indicates this type is a non-null. 'ofType' is a valid field."
    NON_NULL
}`)

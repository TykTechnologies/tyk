package introspection

import (
	"strings"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

const (
	DeprecatedDirectiveName  = "deprecated"
	DeprecationReasonArgName = "reason"
)

type Generator struct {
	Data    *Data
	walker  *astvisitor.Walker
	visitor *introspectionVisitor
}

func NewGenerator() *Generator {
	walker := astvisitor.NewWalker(48)
	visitor := introspectionVisitor{
		Walker: &walker,
	}

	walker.RegisterAllNodesVisitor(&visitor)

	return &Generator{
		walker:  &walker,
		visitor: &visitor,
	}
}

func (g *Generator) Generate(definition *ast.Document, report *operationreport.Report, data *Data) {
	g.visitor.data = data
	g.visitor.definition = definition
	g.walker.Walk(definition, nil, report)
}

type introspectionVisitor struct {
	*astvisitor.Walker
	definition       *ast.Document
	data             *Data
	currentType      FullType
	currentField     Field
	currentDirective Directive
}

func (i *introspectionVisitor) EnterDocument(operation, definition *ast.Document) {
	i.data.Schema = NewSchema()
}

func (i *introspectionVisitor) LeaveDocument(operation, definition *ast.Document) {

}

func (i *introspectionVisitor) EnterObjectTypeDefinition(ref int) {
	i.currentType = NewFullType()
	i.currentType.Name = i.definition.ObjectTypeDefinitionNameString(ref)
	i.currentType.Kind = OBJECT
	i.currentType.Description = i.definition.ObjectTypeDescriptionNameString(ref)
	for _, typeRef := range i.definition.ObjectTypeDefinitions[ref].ImplementsInterfaces.Refs {
		name := i.definition.TypeNameString(typeRef)
		i.currentType.Interfaces = append(i.currentType.Interfaces, TypeRef{
			Kind: INTERFACE,
			Name: &name,
		})
	}
}

func (i *introspectionVisitor) LeaveObjectTypeDefinition(ref int) {
	if strings.HasPrefix(i.currentType.Name, "__") {
		return
	}
	i.data.Schema.Types = append(i.data.Schema.Types, i.currentType)
}

func (i *introspectionVisitor) EnterObjectTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveObjectTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterFieldDefinition(ref int) {
	i.currentField = NewField()
	i.currentField.Name = i.definition.FieldDefinitionNameString(ref)
	i.currentField.Description = i.definition.FieldDefinitionDescriptionString(ref)
	i.currentField.Type = i.TypeRef(i.definition.FieldDefinitionType(ref))

	if i.definition.FieldDefinitionHasDirectives(ref) {
		directiveRef, exists := i.definition.FieldDefinitionDirectiveByName(ref, []byte(DeprecatedDirectiveName))
		if exists {
			i.currentField.IsDeprecated = true
			i.currentField.DeprecationReason = i.deprecationReason(directiveRef)
		}
	}
}

func (i *introspectionVisitor) LeaveFieldDefinition(ref int) {
	if strings.HasPrefix(i.currentField.Name, "__") {
		return
	}
	i.currentType.Fields = append(i.currentType.Fields, i.currentField)
}

func (i *introspectionVisitor) EnterInputValueDefinition(ref int) {
	var defaultValue *string
	if i.definition.InputValueDefinitionHasDefaultValue(ref) {
		value := i.definition.InputValueDefinitionDefaultValue(ref)
		printedValue, err := i.definition.PrintValueBytes(value, nil)
		if err != nil {
			i.StopWithInternalErr(err)
			return
		}
		printedStr := unsafebytes.BytesToString(printedValue)
		defaultValue = &printedStr
	}

	inputValue := InputValue{
		Name:         i.definition.InputValueDefinitionNameString(ref),
		Description:  i.definition.InputValueDefinitionDescriptionString(ref),
		Type:         i.TypeRef(i.definition.InputValueDefinitionType(ref)),
		DefaultValue: defaultValue,
	}

	switch i.Ancestors[len(i.Ancestors)-1].Kind {
	case ast.NodeKindInputObjectTypeDefinition:
		i.currentType.InputFields = append(i.currentType.InputFields, inputValue)
	case ast.NodeKindFieldDefinition:
		i.currentField.Args = append(i.currentField.Args, inputValue)
	case ast.NodeKindDirectiveDefinition:
		i.currentDirective.Args = append(i.currentDirective.Args, inputValue)
	}
}

func (i *introspectionVisitor) LeaveInputValueDefinition(ref int) {

}

func (i *introspectionVisitor) EnterInterfaceTypeDefinition(ref int) {
	i.currentType = NewFullType()
	i.currentType.Kind = INTERFACE
	i.currentType.Name = i.definition.InterfaceTypeDefinitionNameString(ref)
	i.currentType.Description = i.definition.InterfaceTypeDefinitionDescriptionString(ref)

	interfaceNameBytes := i.definition.InterfaceTypeDefinitionNameBytes(ref)
	for objectTypeDefRef := range i.definition.ObjectTypeDefinitions {
		if i.definition.ObjectTypeDefinitionImplementsInterface(objectTypeDefRef, interfaceNameBytes) {
			objectName := i.definition.ObjectTypeDefinitionNameString(objectTypeDefRef)
			i.currentType.PossibleTypes = append(i.currentType.PossibleTypes, TypeRef{
				Kind: OBJECT,
				Name: &objectName,
			})
		}
	}
}

func (i *introspectionVisitor) LeaveInterfaceTypeDefinition(ref int) {
	if strings.HasPrefix(i.currentType.Name, "__") {
		return
	}
	i.data.Schema.Types = append(i.data.Schema.Types, i.currentType)
}

func (i *introspectionVisitor) EnterInterfaceTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveInterfaceTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterScalarTypeDefinition(ref int) {
	typeDefinition := NewFullType()
	typeDefinition.Kind = SCALAR
	typeDefinition.Name = i.definition.ScalarTypeDefinitionNameString(ref)
	typeDefinition.Description = i.definition.ScalarTypeDefinitionDescriptionString(ref)
	i.data.Schema.Types = append(i.data.Schema.Types, typeDefinition)
}

func (i *introspectionVisitor) LeaveScalarTypeDefinition(ref int) {

}

func (i *introspectionVisitor) EnterScalarTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveScalarTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterUnionTypeDefinition(ref int) {
	i.currentType = NewFullType()
	i.currentType.Kind = UNION
	i.currentType.Name = i.definition.UnionTypeDefinitionNameString(ref)
	i.currentType.Description = i.definition.UnionTypeDefinitionDescriptionString(ref)
}

func (i *introspectionVisitor) LeaveUnionTypeDefinition(ref int) {
	if strings.HasPrefix(i.currentType.Name, "__") {
		return
	}
	i.data.Schema.Types = append(i.data.Schema.Types, i.currentType)
}

func (i *introspectionVisitor) EnterUnionTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveUnionTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterUnionMemberType(ref int) {
	name := i.definition.TypeNameString(ref)
	i.currentType.PossibleTypes = append(i.currentType.PossibleTypes, TypeRef{
		Kind: OBJECT,
		Name: &name,
	})
}

func (i *introspectionVisitor) LeaveUnionMemberType(ref int) {

}

func (i *introspectionVisitor) EnterEnumTypeDefinition(ref int) {
	i.currentType = NewFullType()
	i.currentType.Kind = ENUM
	i.currentType.Name = i.definition.EnumTypeDefinitionNameString(ref)
	i.currentType.Description = i.definition.EnumTypeDefinitionDescriptionString(ref)
}

func (i *introspectionVisitor) LeaveEnumTypeDefinition(ref int) {
	if strings.HasPrefix(i.currentType.Name, "__") {
		return
	}
	i.data.Schema.Types = append(i.data.Schema.Types, i.currentType)
}

func (i *introspectionVisitor) EnterEnumTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveEnumTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterEnumValueDefinition(ref int) {

}

func (i *introspectionVisitor) LeaveEnumValueDefinition(ref int) {
	enumValue := EnumValue{
		Name:        i.definition.EnumValueDefinitionNameString(ref),
		Description: i.definition.EnumValueDefinitionDescriptionString(ref),
	}

	if i.definition.EnumValueDefinitionHasDirectives(ref) {
		directiveRef, exists := i.definition.EnumValueDefinitionDirectiveByName(ref, []byte(DeprecatedDirectiveName))
		if exists {
			enumValue.IsDeprecated = true
			enumValue.DeprecationReason = i.deprecationReason(directiveRef)
		}
	}

	i.currentType.EnumValues = append(i.currentType.EnumValues, enumValue)
}

func (i *introspectionVisitor) EnterInputObjectTypeDefinition(ref int) {
	i.currentType = NewFullType()
	i.currentType.Kind = INPUTOBJECT
	i.currentType.Name = i.definition.InputObjectTypeDefinitionNameString(ref)
	i.currentType.Description = i.definition.InputObjectTypeDefinitionDescriptionString(ref)
}

func (i *introspectionVisitor) LeaveInputObjectTypeDefinition(ref int) {
	i.data.Schema.Types = append(i.data.Schema.Types, i.currentType)
}

func (i *introspectionVisitor) EnterInputObjectTypeExtension(ref int) {

}

func (i *introspectionVisitor) LeaveInputObjectTypeExtension(ref int) {

}

func (i *introspectionVisitor) EnterDirectiveDefinition(ref int) {
	i.currentDirective = NewDirective()
	i.currentDirective.Name = i.definition.DirectiveDefinitionNameString(ref)
	i.currentDirective.Description = i.definition.DirectiveDefinitionDescriptionString(ref)
}

func (i *introspectionVisitor) LeaveDirectiveDefinition(ref int) {
	i.data.Schema.Directives = append(i.data.Schema.Directives, i.currentDirective)
}

func (i *introspectionVisitor) EnterDirectiveLocation(location ast.DirectiveLocation) {
	i.currentDirective.Locations = append(i.currentDirective.Locations, location.LiteralString())
}

func (i *introspectionVisitor) LeaveDirectiveLocation(location ast.DirectiveLocation) {

}

func (i *introspectionVisitor) EnterSchemaDefinition(ref int) {

}

func (i *introspectionVisitor) LeaveSchemaDefinition(ref int) {

}

func (i *introspectionVisitor) EnterSchemaExtension(ref int) {

}

func (i *introspectionVisitor) LeaveSchemaExtension(ref int) {

}

func (i *introspectionVisitor) EnterRootOperationTypeDefinition(ref int) {
	switch i.definition.RootOperationTypeDefinitions[ref].OperationType {
	case ast.OperationTypeQuery:
		i.data.Schema.QueryType = &TypeName{
			Name: i.definition.Input.ByteSliceString(i.definition.RootOperationTypeDefinitions[ref].NamedType.Name),
		}
	case ast.OperationTypeMutation:
		i.data.Schema.MutationType = &TypeName{
			Name: i.definition.Input.ByteSliceString(i.definition.RootOperationTypeDefinitions[ref].NamedType.Name),
		}
	case ast.OperationTypeSubscription:
		i.data.Schema.SubscriptionType = &TypeName{
			Name: i.definition.Input.ByteSliceString(i.definition.RootOperationTypeDefinitions[ref].NamedType.Name),
		}
	}
}

func (i *introspectionVisitor) LeaveRootOperationTypeDefinition(ref int) {

}

func (i *introspectionVisitor) EnterOperationDefinition(ref int) {

}

func (i *introspectionVisitor) LeaveOperationDefinition(ref int) {

}

func (i *introspectionVisitor) EnterSelectionSet(ref int) {

}

func (i *introspectionVisitor) LeaveSelectionSet(ref int) {

}

func (i *introspectionVisitor) EnterField(ref int) {

}

func (i *introspectionVisitor) LeaveField(ref int) {

}

func (i *introspectionVisitor) EnterArgument(ref int) {

}

func (i *introspectionVisitor) LeaveArgument(ref int) {

}

func (i *introspectionVisitor) EnterFragmentSpread(ref int) {

}

func (i *introspectionVisitor) LeaveFragmentSpread(ref int) {

}

func (i *introspectionVisitor) EnterInlineFragment(ref int) {

}

func (i *introspectionVisitor) LeaveInlineFragment(ref int) {

}

func (i *introspectionVisitor) EnterFragmentDefinition(ref int) {

}

func (i *introspectionVisitor) LeaveFragmentDefinition(ref int) {

}

func (i *introspectionVisitor) EnterVariableDefinition(ref int) {

}

func (i *introspectionVisitor) LeaveVariableDefinition(ref int) {

}

func (i *introspectionVisitor) EnterDirective(ref int) {

}

func (i *introspectionVisitor) LeaveDirective(ref int) {

}

func (i *introspectionVisitor) TypeRef(typeRef int) TypeRef {
	switch i.definition.Types[typeRef].TypeKind {
	case ast.TypeKindNamed:
		name := i.definition.TypeNameBytes(typeRef)
		node, exists := i.definition.Index.FirstNodeByNameBytes(name)
		if !exists {
			return TypeRef{}
		}
		var typeKind __TypeKind
		switch node.Kind {
		case ast.NodeKindScalarTypeDefinition:
			typeKind = SCALAR
		case ast.NodeKindObjectTypeDefinition:
			typeKind = OBJECT
		case ast.NodeKindEnumTypeDefinition:
			typeKind = ENUM
		case ast.NodeKindInterfaceTypeDefinition:
			typeKind = INTERFACE
		case ast.NodeKindUnionTypeDefinition:
			typeKind = UNION
		case ast.NodeKindInputObjectTypeDefinition:
			typeKind = INPUTOBJECT
		}
		nameStr := unsafebytes.BytesToString(name)
		return TypeRef{
			Kind: typeKind,
			Name: &nameStr,
		}
	case ast.TypeKindNonNull:
		ofType := i.TypeRef(i.definition.Types[typeRef].OfType)
		return TypeRef{
			Kind:   NONNULL,
			OfType: &ofType,
		}
	case ast.TypeKindList:
		ofType := i.TypeRef(i.definition.Types[typeRef].OfType)
		return TypeRef{
			Kind:   LIST,
			OfType: &ofType,
		}
	default:
		return TypeRef{}
	}
}

func (i *introspectionVisitor) deprecationReason(directiveRef int) (reason *string) {
	argValue, exists := i.definition.DirectiveArgumentValueByName(directiveRef, []byte(DeprecationReasonArgName))
	if exists {
		reasonContent := i.definition.ValueContentString(argValue)
		return &reasonContent
	}

	defaultValue := i.definition.DirectiveDefinitionArgumentDefaultValueString(DeprecatedDirectiveName, DeprecationReasonArgName)
	if defaultValue != "" {
		return &defaultValue
	}

	return
}

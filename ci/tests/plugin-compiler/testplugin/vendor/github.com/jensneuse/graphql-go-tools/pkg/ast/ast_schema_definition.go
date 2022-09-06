package ast

import "github.com/jensneuse/graphql-go-tools/pkg/lexer/position"

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
	return d.SchemaDefinitionRef() != InvalidRef
}

func (d *Document) SchemaDefinitionRef() int {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindSchemaDefinition {
			return d.RootNodes[i].Ref
		}
	}

	return InvalidRef
}

func (d *Document) AddSchemaDefinition(schemaDefinition SchemaDefinition) (ref int) {
	d.SchemaDefinitions = append(d.SchemaDefinitions, schemaDefinition)
	return len(d.SchemaDefinitions) - 1
}

func (d *Document) AddSchemaDefinitionRootNode(schemaDefinition SchemaDefinition) {
	ref := d.AddSchemaDefinition(schemaDefinition)
	schemaNode := Node{
		Kind: NodeKindSchemaDefinition,
		Ref:  ref,
	}
	d.RootNodes = append([]Node{schemaNode}, d.RootNodes...)
}

func (d *Document) ImportSchemaDefinition(queryTypeName, mutationTypeName, subscriptionTypeName string) {
	rootOperationTypeRefs := d.ImportRootOperationTypeDefinitions(queryTypeName, mutationTypeName, subscriptionTypeName)

	schemaDefinition := SchemaDefinition{
		RootOperationTypeDefinitions: RootOperationTypeDefinitionList{
			Refs: rootOperationTypeRefs,
		},
	}

	d.AddSchemaDefinitionRootNode(schemaDefinition)
}

func (d *Document) ReplaceRootOperationTypesOfSchemaDefinition(schemaDefinitionRef int, queryTypeName, mutationTypeName, subscriptionTypeName string) {
	d.RootOperationTypeDefinitions = d.RootOperationTypeDefinitions[:0]
	rootOperationTypeRefs := d.ImportRootOperationTypeDefinitions(queryTypeName, mutationTypeName, subscriptionTypeName)
	d.SchemaDefinitions[schemaDefinitionRef].RootOperationTypeDefinitions.Refs = rootOperationTypeRefs
}

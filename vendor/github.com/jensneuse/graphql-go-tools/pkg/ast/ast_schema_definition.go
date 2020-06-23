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
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindSchemaDefinition {
			return true
		}
	}

	return false
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
	var operationRefs []int

	if queryTypeName != "" {
		operationRefs = append(operationRefs, d.ImportRootOperationTypeDefinition(queryTypeName, OperationTypeQuery))
	}
	if mutationTypeName != "" {
		operationRefs = append(operationRefs, d.ImportRootOperationTypeDefinition(mutationTypeName, OperationTypeMutation))
	}
	if subscriptionTypeName != "" {
		operationRefs = append(operationRefs, d.ImportRootOperationTypeDefinition(subscriptionTypeName, OperationTypeSubscription))
	}

	schemaDefinition := SchemaDefinition{
		RootOperationTypeDefinitions: RootOperationTypeDefinitionList{
			Refs: operationRefs,
		},
	}

	d.AddSchemaDefinitionRootNode(schemaDefinition)
}

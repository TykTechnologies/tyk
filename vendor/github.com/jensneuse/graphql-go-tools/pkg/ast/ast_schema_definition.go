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

func (d *Document) AddSchemaDefinition(schemaDefinition SchemaDefinition) (ref int) {
	d.SchemaDefinitions = append(d.SchemaDefinitions, schemaDefinition)
	return len(d.SchemaDefinitions) - 1
}

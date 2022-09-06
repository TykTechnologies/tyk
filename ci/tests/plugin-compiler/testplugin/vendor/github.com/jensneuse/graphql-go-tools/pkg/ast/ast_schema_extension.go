package ast

import "github.com/jensneuse/graphql-go-tools/pkg/lexer/position"

type SchemaExtension struct {
	ExtendLiteral position.Position
	SchemaDefinition
}

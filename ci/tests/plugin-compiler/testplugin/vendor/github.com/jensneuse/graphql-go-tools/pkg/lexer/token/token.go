// Package token contains the object and logic needed to describe a lexed token in a GraphQL document
package token

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/keyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type Token struct {
	Keyword      keyword.Keyword
	Literal      ast.ByteSliceReference
	TextPosition position.Position
}

func (t Token) String() string {
	return fmt.Sprintf("token:: Keyword: %s, Pos: %s", t.Keyword, t.TextPosition)
}

func (t *Token) SetStart(inputPosition int, textPosition position.Position) {
	t.Literal.Start = uint32(inputPosition)
	t.TextPosition.LineStart = textPosition.LineStart
	t.TextPosition.CharStart = textPosition.CharStart
}

func (t *Token) SetEnd(inputPosition int, textPosition position.Position) {
	t.Literal.End = uint32(inputPosition)
	t.TextPosition.LineEnd = textPosition.LineStart
	t.TextPosition.CharEnd = textPosition.CharStart
}

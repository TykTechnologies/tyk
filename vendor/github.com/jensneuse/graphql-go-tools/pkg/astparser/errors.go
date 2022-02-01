package astparser

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/identkeyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/keyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type origin struct {
	file     string
	line     int
	funcName string
}

// ErrUnexpectedToken is a custom error object containing all necessary information to properly render an unexpected token error
type ErrUnexpectedToken struct {
	keyword  keyword.Keyword
	expected []keyword.Keyword
	position position.Position
	literal  string
	origins  []origin
}

func (e ErrUnexpectedToken) Error() string {

	origins := ""
	for _, origin := range e.origins {
		origins = origins + fmt.Sprintf("\n\t\t%s:%d\n\t\t%s", origin.file, origin.line, origin.funcName)
	}

	return fmt.Sprintf("unexpected token - keyword: '%s' literal: '%s' - expected: '%s' position: '%s'%s", e.keyword, e.literal, e.expected, e.position, origins)
}

// ErrUnexpectedIdentKey is a custom error object to properly render an unexpected ident key error
type ErrUnexpectedIdentKey struct {
	keyword  identkeyword.IdentKeyword
	expected []identkeyword.IdentKeyword
	position position.Position
	literal  string
	origins  []origin
}

func (e ErrUnexpectedIdentKey) Error() string {

	origins := ""
	for _, origin := range e.origins {
		origins = origins + fmt.Sprintf("\n\t\t%s:%d\n\t\t%s", origin.file, origin.line, origin.funcName)
	}

	return fmt.Sprintf("unexpected ident - keyword: '%s' literal: '%s' - expected: '%s' position: '%s'%s", e.keyword, e.literal, e.expected, e.position, origins)
}

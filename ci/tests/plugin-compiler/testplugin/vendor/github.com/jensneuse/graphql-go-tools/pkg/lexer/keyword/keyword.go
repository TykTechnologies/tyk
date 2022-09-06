//go:generate stringer -type=Keyword

// Package keyword contains all possible GraphQL keywords
package keyword

type Keyword int

const (
	UNDEFINED Keyword = iota
	IDENT
	COMMENT
	EOF

	COLON
	BANG
	LT
	TAB
	SPACE
	COMMA
	AT
	DOT
	SPREAD
	PIPE
	SLASH
	EQUALS
	SUB
	AND
	QUOTE

	DOLLAR
	STRING
	BLOCKSTRING
	INTEGER
	FLOAT

	LPAREN
	RPAREN
	LBRACK
	RBRACK
	LBRACE
	RBRACE
)

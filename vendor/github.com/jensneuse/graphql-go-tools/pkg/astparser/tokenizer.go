package astparser

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/keyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/token"
)

// Tokenizer takes a raw input and turns it into set of tokens
type Tokenizer struct {
	lexer        *lexer.Lexer
	tokens       []token.Token
	maxTokens    int
	currentToken int
	skipComments bool
}

// NewTokenizer returns a new tokenizer
func NewTokenizer() *Tokenizer {
	return &Tokenizer{
		tokens:       make([]token.Token, 256),
		lexer:        &lexer.Lexer{},
		skipComments: true,
	}
}

func (t *Tokenizer) Tokenize(input *ast.Input) {
	t.lexer.SetInput(input)
	t.tokens = t.tokens[:0]

	for {
		next := t.lexer.Read()
		if next.Keyword == keyword.EOF {
			t.maxTokens = len(t.tokens)
			t.currentToken = -1
			return
		}
		t.tokens = append(t.tokens, next)
	}
}

// hasNextToken - checks that we haven't reached eof
func (t *Tokenizer) hasNextToken(skip int) bool {
	return t.currentToken+1+skip < t.maxTokens
}

// next - increments current token index if hasNextToken
// otherwise returns current token
func (t *Tokenizer) next() int {
	if t.hasNextToken(0) {
		t.currentToken++
	}
	return t.currentToken
}

// Read - increments currentToken index and return token if hasNextToken
// otherwise returns keyword.EOF
func (t *Tokenizer) Read() token.Token {
	tok := t.read()
	if t.skipComments && tok.Keyword == keyword.COMMENT {
		tok = t.read()
	}

	return tok
}

func (t *Tokenizer) read() token.Token {
	if t.hasNextToken(0) {
		return t.tokens[t.next()]
	}

	return token.Token{
		Keyword: keyword.EOF,
	}
}

// Peek - returns token next to currentToken if hasNextToken
// otherwise returns keyword.EOF
func (t *Tokenizer) Peek() token.Token {
	tok := t.peek(0)
	if t.skipComments && tok.Keyword == keyword.COMMENT {
		tok = t.peek(1)
	}

	return tok
}

func (t *Tokenizer) peek(skip int) token.Token {
	if t.hasNextToken(skip) {
		nextIndex := t.currentToken + 1 + skip
		return t.tokens[nextIndex]
	}
	return token.Token{
		Keyword: keyword.EOF,
	}
}

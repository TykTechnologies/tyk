package astparser

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/identkeyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/keyword"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/token"
)

// read - reads and returns next token
func (p *Parser) read() token.Token {
	return p.tokenizer.Read()
}

// peek - returns token next to currentToken
// returns keyword.EOF when reached end of document
func (p *Parser) peek() keyword.Keyword {
	tok := p.tokenizer.Peek()
	return tok.Keyword
}

// peekLiteral - returns keyword.Keyword and literal ast.ByteSliceReference of token next to currentToken
// returns keyword.EOF when reached end of document
func (p *Parser) peekLiteral() (keyword.Keyword, ast.ByteSliceReference) {
	tok := p.tokenizer.Peek()
	if tok.Keyword != keyword.EOF {
		return tok.Keyword, tok.Literal
	}
	return keyword.EOF, ast.ByteSliceReference{}
}

// peekEquals - checks that next token keyword is equal to key
func (p *Parser) peekEquals(key keyword.Keyword) bool {
	return p.peek() == key
}

// peekEqualsIdentKey - checks that next token is an identifier of the given key
func (p *Parser) peekEqualsIdentKey(identKey identkeyword.IdentKeyword) bool {
	key, literal := p.peekLiteral()
	if key != keyword.IDENT {
		return false
	}
	actualKey := p.identKeywordSliceRef(literal)
	return actualKey == identKey
}

func (p *Parser) mustRead(key keyword.Keyword) (next token.Token) {
	next = p.read()
	if next.Keyword != key {
		p.errUnexpectedToken(next, key)
	}
	return
}

func (p *Parser) mustReadIdentKey(key identkeyword.IdentKeyword) (next token.Token) {
	next = p.read()
	if next.Keyword != keyword.IDENT {
		p.errUnexpectedToken(next, keyword.IDENT)
	}
	identKey := p.identKeywordToken(next)
	if identKey != key {
		p.errUnexpectedIdentKey(next, identKey, key)
	}
	return
}

func (p *Parser) mustReadExceptIdentKey(key identkeyword.IdentKeyword) (next token.Token) {
	next = p.read()
	if next.Keyword != keyword.IDENT {
		p.errUnexpectedToken(next, keyword.IDENT)
	}
	identKey := p.identKeywordToken(next)
	if identKey == key {
		p.errUnexpectedIdentKey(next, identKey, key)
	}
	return
}

func (p *Parser) mustReadOneOf(keys ...identkeyword.IdentKeyword) (token.Token, identkeyword.IdentKeyword) {
	next := p.read()

	identKey := p.identKeywordToken(next)
	for _, expectation := range keys {
		if identKey == expectation {
			return next, identKey
		}
	}
	p.errUnexpectedToken(next)
	return next, identKey
}

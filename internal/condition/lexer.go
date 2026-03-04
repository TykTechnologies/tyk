package condition

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenType int

const (
	tokenIdent    tokenType = iota // identifier (e.g. request, method)
	tokenDot                       // .
	tokenLBracket                  // [
	tokenRBracket                  // ]
	tokenString                    // "..." quoted string
	tokenLParen                    // (
	tokenRParen                    // )
	tokenAnd                       // &&
	tokenOr                        // ||
	tokenNot                       // !
	tokenEq                        // ==
	tokenNeq                       // !=
	tokenContains                  // contains
	tokenMatches                   // matches
	tokenEOF
)

type token struct {
	typ tokenType
	val string
}

type lexer struct {
	input string
	pos   int
}

func newLexer(input string) *lexer {
	return &lexer{input: input}
}

func (l *lexer) tokenize() ([]token, error) {
	var tokens []token
	for {
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
		if tok.typ == tokenEOF {
			break
		}
	}
	return tokens, nil
}

func (l *lexer) next() (token, error) {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return token{tokenEOF, ""}, nil
	}

	ch := l.input[l.pos]

	switch ch {
	case '.':
		l.pos++
		return token{tokenDot, "."}, nil
	case '[':
		l.pos++
		return token{tokenLBracket, "["}, nil
	case ']':
		l.pos++
		return token{tokenRBracket, "]"}, nil
	case '(':
		l.pos++
		return token{tokenLParen, "("}, nil
	case ')':
		l.pos++
		return token{tokenRParen, ")"}, nil
	case '&':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '&' {
			l.pos += 2
			return token{tokenAnd, "&&"}, nil
		}
		return token{}, fmt.Errorf("unexpected character '&' at position %d", l.pos)
	case '|':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '|' {
			l.pos += 2
			return token{tokenOr, "||"}, nil
		}
		return token{}, fmt.Errorf("unexpected character '|' at position %d", l.pos)
	case '=':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
			l.pos += 2
			return token{tokenEq, "=="}, nil
		}
		return token{}, fmt.Errorf("unexpected character '=' at position %d", l.pos)
	case '!':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
			l.pos += 2
			return token{tokenNeq, "!="}, nil
		}
		l.pos++
		return token{tokenNot, "!"}, nil
	case '"':
		return l.readString()
	default:
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			return l.readIdent(), nil
		}
		return token{}, fmt.Errorf("unexpected character %q at position %d", string(ch), l.pos)
	}
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) && l.input[l.pos] == ' ' {
		l.pos++
	}
}

func (l *lexer) readString() (token, error) {
	l.pos++ // skip opening quote
	var sb strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			l.pos++
			sb.WriteByte(l.input[l.pos])
			l.pos++
			continue
		}
		if ch == '"' {
			l.pos++
			return token{tokenString, sb.String()}, nil
		}
		sb.WriteByte(ch)
		l.pos++
	}
	return token{}, fmt.Errorf("unterminated string")
}

func (l *lexer) readIdent() token {
	start := l.pos
	for l.pos < len(l.input) && (unicode.IsLetter(rune(l.input[l.pos])) || unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '_') {
		l.pos++
	}
	val := l.input[start:l.pos]
	switch val {
	case "contains":
		return token{tokenContains, val}
	case "matches":
		return token{tokenMatches, val}
	default:
		return token{tokenIdent, val}
	}
}

package condition

import "fmt"

// AST node types

type astNode interface {
	astNode()
}

type binaryNode struct {
	op    tokenType
	left  astNode
	right astNode
}

func (*binaryNode) astNode() {}

type notNode struct {
	operand astNode
}

func (*notNode) astNode() {}

// accessorRef identifies a data source: namespace.field or namespace.field["key"]
type accessorRef struct {
	namespace string // request, context, session
	field     string // method, path, headers, params, metadata, or "" for context["key"]
	key       string // bracket key for headers, params, metadata, context
}

type comparisonNode struct {
	left  accessorRef
	op    tokenType
	right string // the string literal to compare against
}

func (*comparisonNode) astNode() {}

// parser is a recursive descent parser for condition expressions.
type parser struct {
	tokens []token
	pos    int
}

func newParser(tokens []token) *parser {
	return &parser{tokens: tokens}
}

func (p *parser) parse() (astNode, error) {
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().typ != tokenEOF {
		return nil, fmt.Errorf("unexpected token %q at end of expression", p.peek().val)
	}
	return node, nil
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tokenEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) advance() token {
	tok := p.peek()
	p.pos++
	return tok
}

func (p *parser) parseOr() (astNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokenOr {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op: tokenOr, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (astNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokenAnd {
		p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op: tokenAnd, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseNot() (astNode, error) {
	if p.peek().typ == tokenNot {
		p.advance()
		operand, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &notNode{operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (astNode, error) {
	if p.peek().typ == tokenLParen {
		p.advance()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().typ != tokenRParen {
			return nil, fmt.Errorf("expected ')', got %q", p.peek().val)
		}
		p.advance()
		return node, nil
	}

	return p.parseComparison()
}

func (p *parser) parseComparison() (astNode, error) {
	ref, err := p.parseAccessorRef()
	if err != nil {
		return nil, err
	}

	op := p.peek()
	switch op.typ {
	case tokenEq, tokenNeq, tokenContains, tokenMatches:
		p.advance()
	default:
		return nil, fmt.Errorf("expected comparison operator, got %q", op.val)
	}

	if p.peek().typ != tokenString {
		return nil, fmt.Errorf("expected string literal, got %q", p.peek().val)
	}
	val := p.advance().val

	return &comparisonNode{left: ref, op: op.typ, right: val}, nil
}

func (p *parser) parseAccessorRef() (accessorRef, error) {
	if p.peek().typ != tokenIdent {
		return accessorRef{}, fmt.Errorf("expected identifier, got %q", p.peek().val)
	}
	namespace := p.advance().val

	// context["key"] — shorthand without .field
	if namespace == "context" && p.peek().typ == tokenLBracket {
		p.advance()
		if p.peek().typ != tokenString {
			return accessorRef{}, fmt.Errorf("expected string key in brackets")
		}
		key := p.advance().val
		if p.peek().typ != tokenRBracket {
			return accessorRef{}, fmt.Errorf("expected ']'")
		}
		p.advance()
		return accessorRef{namespace: "context", key: key}, nil
	}

	if p.peek().typ != tokenDot {
		return accessorRef{}, fmt.Errorf("expected '.' after namespace %q", namespace)
	}
	p.advance()

	if p.peek().typ != tokenIdent {
		return accessorRef{}, fmt.Errorf("expected field name after '.'")
	}
	field := p.advance().val

	// Check for bracket accessor: headers["K"], params["K"], metadata["key"]
	var key string
	if p.peek().typ == tokenLBracket {
		p.advance()
		if p.peek().typ != tokenString {
			return accessorRef{}, fmt.Errorf("expected string key in brackets")
		}
		key = p.advance().val
		if p.peek().typ != tokenRBracket {
			return accessorRef{}, fmt.Errorf("expected ']'")
		}
		p.advance()
	}

	return accessorRef{namespace: namespace, field: field, key: key}, nil
}

package pathnormalizer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/TykTechnologies/tyk/common/option"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	slash                 = '/'
	curlyBraceLeft        = '{'
	curlyBraceRight       = '}'
	muxIdPatternSeparator = ':'

	// RePrefix default regexp prefix.
	RePrefix            = "customRegex"
	DefaultNonDefinedRe = "[^/]+"
)

var (
	ErrUnreachableCase  = errors.New("unreachable case")
	ErrUnexpectedSlash  = errors.New("unexpected slash symbol in pattern")
	ErrUnexpectedSymbol = errors.New("unexpected symbol")
)

// Parser responsible for parsing user-defined path of given OAS.
type Parser struct {
	anonymousReCounter int
	prefix             string
	stripSlashes       bool
	ctrResets          bool
}

// WithNoStripSlashes skip strip slashes.
// Removes slashes near each other.
func WithNoStripSlashes() option.Option[Parser] {
	return func(parser *Parser) {
		parser.stripSlashes = false
	}
}

// WithPrefix allows to use custom prefix.
func WithPrefix(prefix string) option.Option[Parser] {
	return func(parser *Parser) {
		parser.prefix = prefix
	}
}

// WithCtrResets enables counter resets on each parse call.
// Useful for testing.
func WithCtrResets() option.Option[Parser] {
	return func(parser *Parser) {
		parser.ctrResets = true
	}
}

// NewParser instantiates new parser instance
func NewParser(opts ...option.Option[Parser]) *Parser {
	return option.New(opts).Build(Parser{
		anonymousReCounter: 0,
		prefix:             RePrefix,
		stripSlashes:       true,
		ctrResets:          false,
	})
}

// Parse responsible for parsing next one path.
func (p *Parser) Parse(path string) (*NormalizedPath, error) {
	if p.ctrResets {
		defer func() {
			p.anonymousReCounter = 0
		}()
	}

	singlePathParser := newPathParser(path, p)

	pPath, err := singlePathParser.parse()

	if err != nil {
		return nil, err
	}

	return newNormalizedPath(pPath), nil
}

type pathParser struct {
	src    string
	pos    int
	parent *Parser
}

func newPathParser(path string, parent *Parser) *pathParser {
	return &pathParser{
		src:    path,
		pos:    0,
		parent: parent,
	}
}

func (p *pathParser) parse() ([]pathPart, error) {
	var parts []pathPart

	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		var err error
		var part pathPart

		switch {
		case ch == slash:
			if p.parent.stripSlashes {
				p.consumeAll(slash)
			} else {
				p.consumeOne(slash)
			}

			part = newPathPartSplitter()
		case ch == curlyBraceLeft:
			part, err = p.parseMuxRe()
		default:
			if id, ok := p.consumeStaticPart(); ok {
				part = newPathPartRaw(id)
				break
			}

			part, err = p.parseAnonymousRe()
		}

		if err != nil {
			return nil, err
		}

		parts = append(parts, part)
	}

	return parts, nil
}

func (p *pathParser) consumeMuxIdentifier() (res string, ok bool, finished bool) {
	if !isLetter(p.src[p.pos]) {
		return
	}

	start := p.pos
	for p.pos < len(p.src) && isMuxIdentifierSymbol(p.src[p.pos]) {
		p.pos++
	}

	// end reached
	if p.pos == len(p.src) {
		p.pos = start
		return
	}

	if p.src[p.pos] == muxIdPatternSeparator {
		p.pos++
		return p.src[start : p.pos-1], true, false
	}

	if p.src[p.pos] == curlyBraceRight {
		p.pos++
		return p.src[start : p.pos-1], true, true
	}

	p.pos = start
	return
}

func (p *pathParser) parseMuxRe() (pathPart, error) {
	if p.src[p.pos] != curlyBraceLeft {
		return pathPart{}, ErrUnreachableCase
	}

	// consume first open curly brace
	p.pos++
	openBraceCtr := 1

	paramName, idParsedOk, isFinished := p.consumeMuxIdentifier()

	if isFinished {
		return p.newPathPartRe(paramName, DefaultNonDefinedRe)
	}

	start := p.pos
loop:
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		p.pos++

		switch ch {
		case slash:
			p.pos--
			break loop
		case curlyBraceLeft:
			openBraceCtr++
		case curlyBraceRight:
			openBraceCtr--
			if openBraceCtr == 0 {
				// if next exists it should be /
				if p.pos < len(p.src) && p.src[p.pos] != slash {
					return pathPart{}, p.parseError(ErrUnexpectedSymbol)
				}

				break loop
			}
		default:
		}
	}

	if openBraceCtr != 0 {
		p.pos--
		return pathPart{}, p.parseError(ErrUnexpectedSlash)
	}

	if !idParsedOk {
		paramName = p.newAnonymousName()
	}

	return p.newPathPartRe(paramName, p.src[start:p.pos-1])
}

func (p *pathParser) parseError(err error) parseError {
	return parseError{
		prev: err,
		pos:  p.pos,
		src:  p.src,
	}
}

func (p *pathParser) parseAnonymousRe() (pathPart, error) {
	paramName, idParsedOk, isFinished := p.consumeMuxIdentifier()

	if isFinished {
		return pathPart{}, p.parseError(ErrUnreachableCase)
	}

	start := p.pos
	braceCtr := 0

loop:
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		p.pos++

		switch ch {
		case slash:
			p.pos--
			break loop
		case curlyBraceLeft:
			braceCtr++
		case curlyBraceRight:
			braceCtr--
		}
	}

	if braceCtr != 0 {
		return pathPart{}, p.parseError(ErrUnexpectedSlash)
	}

	if !idParsedOk {
		paramName = p.newAnonymousName()
	}

	return p.newPathPartRe(
		paramName,
		p.src[start:p.pos],
	)
}

func (p *pathParser) consumeAll(ch byte) {
	for p.consumeOne(ch) {
	}
}

func (p *pathParser) consumeOne(ch byte) bool {
	if p.pos < len(p.src) && p.src[p.pos] == ch {
		p.pos++
		return true
	}

	return false
}

func (p *pathParser) consumeStaticPart() (string, bool) {
	var b []byte
	var pos = p.pos

loop:
	for pos < len(p.src) {
		ch := p.src[pos]
		pos++

		switch {
		case ch == slash:
			pos--
			break loop
		case !isIdentifierSymbol(ch):
			return "", false
		default:
			b = append(b, ch)
		}
	}

	p.pos = pos
	return string(b), len(b) > 0
}

func (p *pathParser) newAnonymousName() string {
	p.parent.anonymousReCounter++
	return fmt.Sprintf("%s%d", p.parent.prefix, p.parent.anonymousReCounter)
}

func (p *pathParser) newPathPartRe(name, pattern string) (pathPart, error) {
	if _, err := regexp.Compile(fmt.Sprintf("^%s$", pattern)); err != nil {
		return pathPart{}, p.parseError(err)
	}

	return pathPart{
		name:    name,
		pattern: pattern,
		typ:     pathPartRe,
		parameter: openapi3.
			NewPathParameter(name).
			WithSchema(openapi3.NewStringSchema().WithPattern(pattern)),
	}, nil
}

type parseError struct {
	prev error
	src  string
	pos  int
}

func (e parseError) Error() string {
	baseMsg := fmt.Sprintf(`failed to parse "%s" at %d`, e.src, e.pos)

	if e.prev == nil {
		return baseMsg
	}

	return fmt.Sprintf(`%s: %s`, baseMsg, e.prev.Error())
}

type pathPartType struct {
	val string
}

var (
	pathPartRe       = pathPartType{"reg-exp"}
	pathPartRaw      = pathPartType{"raw"}
	pathPartSplitter = pathPartType{"/"}
)

// pathPart regular expression part.
type pathPart struct {
	name      string
	pattern   string
	parameter *openapi3.Parameter
	typ       pathPartType
}

func newPathPartSplitter() pathPart {
	return pathPart{
		typ: pathPartSplitter,
	}
}

func newPathPartRaw(name string) pathPart {
	return pathPart{
		name: name,
		typ:  pathPartRaw,
	}
}

func (r *pathPart) normalize() string {
	switch r.typ {
	case pathPartSplitter:
		return "/"
	case pathPartRaw:
		return r.name
	case pathPartRe:
		var sb strings.Builder
		sb.Grow(len(r.name) + 2)
		sb.WriteRune(curlyBraceLeft)
		sb.WriteString(r.name)
		sb.WriteRune(curlyBraceRight)
		return sb.String()
	default:
		panic("invalid path part type")
	}
}

func isIdentifierSymbol(s byte) bool {
	return isLowerLetter(s) || isUpperLetter(s) || isDigit(s) || isOneOf(s, "._-")
}

func isMuxIdentifierSymbol(s byte) bool {
	return isLowerLetter(s) || isUpperLetter(s) || isDigit(s) || isOneOf(s, "_-")
}

func isLetter(s byte) bool {
	return isLowerLetter(s) || isUpperLetter(s)
}

func isLowerLetter(s byte) bool {
	return s >= 'a' && s <= 'z'
}

func isUpperLetter(s byte) bool {
	return s >= 'A' && s <= 'Z'
}

func isDigit(s byte) bool {
	return s >= '0' && s <= '9'
}

func isOneOf(s byte, str string) bool {
	for _, r := range []byte(str) {
		if r == s {
			return true
		}
	}

	return false
}

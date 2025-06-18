package pathnormalizer

import (
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/common/option"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	pathSeparator   = '/'
	curlyBraceLeft  = '{'
	curlyBraceRight = '}'

	// RePrefix default regexp prefix.
	RePrefix = "customRegex"
)

// Parser responsible for parsing user-defined path of given OAS.
type Parser struct {
	customReCounter int
	prefix          string
	stripSlashes    bool
}

// WithNoStripSlashes skip strip slashes.
// Removes slashes near each other.
func WithNoStripSlashes() option.Option[Parser] {
	return func(parser *Parser) {
		parser.stripSlashes = false
	}
}

// WithPrefix allows to us custom prefix.
func WithPrefix(prefix string) option.Option[Parser] {
	return func(parser *Parser) {
		parser.prefix = prefix
	}
}

// NewParser instantiates new parser instance
func NewParser(opts ...option.Option[Parser]) *Parser {
	return option.New(opts).Build(Parser{
		customReCounter: 0,
		prefix:          RePrefix,
		stripSlashes:    true,
	})
}

// Parse responsible for parsing next one path.
func (p *Parser) Parse(path string) (*NormalizedPath, error) {
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
		case ch == pathSeparator:
			if p.parent.stripSlashes {
				p.consumeAll(pathSeparator)
			} else {
				p.consumeOne(pathSeparator)
			}

			part = newPathPartSplitter()
		case ch == curlyBraceLeft:
			part, err = p.parseMuxRe()
		default:
			if id, ok := p.consumeIdentifier(); ok {
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

func (p *pathParser) parseMuxRe() (pathPart, error) {
	var zero pathPart

	return zero, errors.New("parseMuxRe not implemented")
}

func (p *pathParser) parseAnonymousRe() (pathPart, error) {
	start := p.pos

	for p.pos < len(p.src) && p.src[p.pos] != pathSeparator {
		p.pos++
	}

	pattern := p.src[start:p.pos]
	if _, err := regexp.Compile(fmt.Sprintf("^%s$", pattern)); err != nil {
		var zero pathPart
		return zero, parseError{
			prev: err,
			pos:  start,
			src:  p.src,
		}
	}

	return p.newPathPartRe(pattern), nil
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

func (p *pathParser) consumeIdentifier() (string, bool) {
	var b []byte
	var pos = p.pos

loop:
	for pos < len(p.src) {
		ch := p.src[pos]
		pos++

		switch {
		case ch == pathSeparator:
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

func (p *pathParser) newPathPartRe(pattern string) pathPart {
	p.parent.customReCounter++

	name := fmt.Sprintf("%s%d", p.parent.prefix, p.parent.customReCounter)

	return pathPart{
		name:    name,
		pattern: pattern,
		typ:     pathPartRe,
		parameter: openapi3.
			NewPathParameter(name).
			WithSchema(openapi3.NewStringSchema().WithPattern(pattern)),
	}
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

func isLowerLetter(s byte) bool {
	return s >= 'a' && s <= 'z'
}

func isUpperLetter(s byte) bool {
	return s >= 'A' && s <= 'Z'
}

func isDigit(s byte) bool {
	return s >= '0' && s <= '0'
}

func isOneOf(s byte, str string) bool {
	for _, r := range []byte(str) {
		if r == s {
			return true
		}
	}

	return false
}

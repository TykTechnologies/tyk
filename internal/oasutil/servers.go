package oasutil

import (
	"errors"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"strings"
)

var (
	ErrParse                = errors.New("failed to parse")
	ErrEmptyVariableName    = errors.New("empty variable name")
	ErrVariableCollision    = errors.New("variable collision")
	ErrUnexpectedCurlyBrace = errors.New("unexpected closing curly brace")
	errUnreachable          = errors.New("unreachable")
)

const (
	DefaultServerUrlPrefix = "pathParam"
	openCurlyBrace         = '{'
	closeCurlyBrace        = '}'
)

type ServerUrl struct {
	// Url template acceptable by tyk extension
	// eg "{subdomain:[a-z]+}.example.com" or "api.example.com"
	Url string

	// UrlNormalized acceptable by oas specification
	// "{subdomain}.example.com"
	UrlNormalized string

	// Variables server variables
	Variables map[string]*openapi3.ServerVariable
}

// ParseServerUrl
// Url template e.g. "{subdomain:[a-z]+}.example.com" or "api.example.com"
func ParseServerUrl(url string) (*ServerUrl, error) {
	var parser serverUrlParser
	return parser.parse(url)
}

type serverUrlParser struct {
	url     string
	pos     int
	counter int
}

type serverVariable struct {
	name, pattern string
}

func (p *serverUrlParser) parse(url string) (*ServerUrl, error) {
	p.url = url

	result := new(ServerUrl)
	result.Url = url
	result.UrlNormalized = ""

	var buf []byte

	for p.pos < len(url) {
		ch := url[p.pos]

		switch ch {
		case closeCurlyBrace:
			return nil, ErrUnexpectedCurlyBrace

		case openCurlyBrace:
			result.UrlNormalized += string(buf)
			buf = nil

			variable, err := p.extractValueBetweenBraces()

			if err != nil {
				return nil, err
			}

			if result.Variables == nil {
				result.Variables = map[string]*openapi3.ServerVariable{}
			}

			if _, ok := result.Variables[variable.name]; ok {
				return nil, ErrVariableCollision
			}

			result.Variables[variable.name] = &openapi3.ServerVariable{
				Default: p.nextParamName(),
			}

			result.UrlNormalized += string(openCurlyBrace) + variable.name + string(closeCurlyBrace)

		default:
			buf = append(buf, ch)
			p.pos++
		}
	}

	result.UrlNormalized += string(buf)

	return result, nil
}

func (p *serverUrlParser) extractValueBetweenBraces() (serverVariable, error) {
	if p.url[p.pos] != openCurlyBrace {
		return serverVariable{}, errUnreachable
	}

	p.pos++
	start := p.pos

	for p.pos < len(p.url) {
		ch := p.url[p.pos]

		switch {
		case ch == closeCurlyBrace && p.pos == start:
			return serverVariable{}, ErrEmptyVariableName
		case ch == closeCurlyBrace:
			p.pos++

			var contents = p.url[start : p.pos-1]
			var name = contents
			var pattern = ""

			if pos := strings.Index(contents, ":"); pos != -1 {
				name = contents[:pos]
				pattern = contents[pos+1:]
			}

			if len(contents) == 0 || len(name) == 0 {
				return serverVariable{}, ErrEmptyVariableName
			}

			return serverVariable{
				name:    name,
				pattern: pattern,
			}, nil
		default:
			p.pos++
		}
	}

	return serverVariable{}, fmt.Errorf("%w: expected closing curly brace at position %d", ErrParse, p.pos)
}

func (p *serverUrlParser) nextParamName() string {
	p.counter++
	return fmt.Sprintf("%s%d", DefaultServerUrlPrefix, p.counter)
}

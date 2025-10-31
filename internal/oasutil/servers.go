package oasutil

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/TykTechnologies/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

var (
	ErrParse                = errors.New("failed to parse")
	ErrEmptyVariableName    = errors.New("empty variable name")
	ErrVariableCollision    = errors.New("variable collision")
	ErrUnexpectedCurlyBrace = errors.New("unexpected closing curly brace")
	ErrInvalidVariableName  = errors.New("invalid variable name")
	ErrInvalidPattern       = errors.New("invalid pattern")
	ErrNoCaptureGroup       = errors.New("capture groups are prohibited")
	errUnreachable          = errors.New("unreachable")
)

var (
	identifierRe = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9_]*$")
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

func newServerUrl(originUrl string) ServerUrl {
	return ServerUrl{
		Url: originUrl,
	}
}

func (u *ServerUrl) addVariable(name, defaultValue string) error {
	if u.Variables == nil {
		u.Variables = make(map[string]*openapi3.ServerVariable)
	}

	if _, ok := u.Variables[name]; ok {
		return ErrVariableCollision
	}

	u.Variables[name] = &openapi3.ServerVariable{
		Default: defaultValue,
	}

	return nil
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

	result := newServerUrl(url)

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

			if err = result.addVariable(variable.name, p.nextParamName()); err != nil {
				return nil, err
			}

			result.UrlNormalized += string(openCurlyBrace) + variable.name + string(closeCurlyBrace)

		default:
			buf = append(buf, ch)
			p.pos++
		}
	}

	result.UrlNormalized += string(buf)

	return &result, nil
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

			if !isValidIdentifier(name) {
				return serverVariable{}, ErrInvalidVariableName
			}

			if re, err := regexp.Compile(pattern); err != nil {
				return serverVariable{}, errpack.Domain("failed to compile pattern").Chain(ErrInvalidPattern)
			} else if hasCaptureGroups(re) {
				return serverVariable{}, errpack.Domain("using capture group is not allowed in server patterns").Chain(ErrNoCaptureGroup)
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

func isValidIdentifier(name string) bool {
	return identifierRe.MatchString(name)
}

func hasCaptureGroups(re *regexp.Regexp) bool {
	return re.NumSubexp() > 0
}

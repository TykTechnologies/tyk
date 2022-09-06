// byte_templating is intended to offer a simple templating engine for byte slices
// it's different from other implementations in two ways
// 1. you can define the "item" selector on your own, that is you don't have to supply a interface{} object, similar to https://github.com/valyala/fasttemplate
// 2. in addition to fasttemplate you can also define custom directives like "toLower", "URLEncode" etc.
// This library doesn't push any gc pressure to the user
// This library is not thread safe, use it with a sync.Pool
package byte_template

import (
	"bytes"
	"io"
)

type Template struct {
	baseTemplate
	input        []byte
	fetch        Fetch
	directives   []DirectiveDefinition
	buf          bytes.Buffer
	instructions []instruction
}

type baseTemplate struct {
	startToken byte
	endToken   byte
}

var defaultBaseTemplate = baseTemplate{
	startToken: '{',
	endToken:   '}',
}

type Fetch func(w io.Writer, path []byte) (n int, err error)

func New(directiveDefinitions ...DirectiveDefinition) *Template {
	return &Template{
		baseTemplate: defaultBaseTemplate,
		directives:   directiveDefinitions,
	}
}

type instructionKind int

const (
	write instructionKind = iota + 1
	template
)

type instruction struct {
	kind      instructionKind
	start     int
	end       int
	directive arg
	item      arg
}

type arg struct {
	defined bool
	start   int
	end     int
}

func (t *Template) Execute(w io.Writer, input []byte, fetch Fetch) (n int, err error) {

	t.input = input
	t.instructions = t.instructions[:0]
	t.fetch = fetch

	var (
		lastPosition   int
		insideTemplate bool
		insideItem     bool
	)

	length := len(t.input)
	for i := 1; i < length; i++ {
		switch t.input[i] {
		case t.startToken:
			if !insideTemplate && t.input[i-1] == t.startToken {
				insideTemplate = true
				t.instructions = append(t.instructions, instruction{
					kind:  write,
					start: lastPosition,
					end:   i - 1,
				}, instruction{
					kind: template,
				})
				i = i + 1
			}
		case t.endToken:
			if i+1 < length && t.input[i+1] == t.endToken {
				insideTemplate = false
				i = i + 2
				lastPosition = i
			}
		}
		if insideTemplate {
			switch {
			case !insideItem && !t.byteIsWhitespace(t.input[i]):
				lastPosition = i
				insideItem = true
			case len(t.instructions) != 0 && (insideItem && i+1 < length && t.byteIsWhitespace(t.input[i+1]) ||
				insideItem && i+2 < length && t.input[i+1] == t.endToken && t.input[i+2] == t.endToken):
				if t.input[lastPosition] == '.' {
					// item
					t.instructions[len(t.instructions)-1].item.start = lastPosition
					t.instructions[len(t.instructions)-1].item.end = i + 1
					t.instructions[len(t.instructions)-1].item.defined = true
				} else {
					// directive
					t.instructions[len(t.instructions)-1].directive.start = lastPosition
					t.instructions[len(t.instructions)-1].directive.end = i + 1
					t.instructions[len(t.instructions)-1].directive.defined = true
				}
				insideItem = false
				lastPosition = i + 1
			}
		}
	}

	if len(t.instructions) == 0 {
		return w.Write(t.input)
	} else {
		t.instructions = append(t.instructions, instruction{
			kind:  write,
			start: lastPosition,
			end:   length,
		})
	}

	return t.executeInstructions(w, t.instructions)
}

func (t *Template) executeInstructions(w io.Writer, instructions []instruction) (n int, err error) {
	for i := range instructions {
		switch instructions[i].kind {
		case write:
			n, err = w.Write(t.input[instructions[i].start:instructions[i].end])
			if err != nil {
				return
			}
		case template:
			itemPath := t.input[instructions[i].item.start:instructions[i].item.end]
			t.buf.Reset()
			n, err = t.fetch(&t.buf, itemPath)
			if err != nil {
				return
			}

			if instructions[i].directive.defined {
				directiveName := t.input[instructions[i].directive.start:instructions[i].directive.end]
				for k := range t.directives {
					if bytes.Equal(directiveName, t.directives[k].Name) {
						n, err = t.directives[k].Resolve(w, t.buf.Bytes())
						if err != nil {
							return
						}
					}
				}
			} else {
				_, err = t.buf.WriteTo(w)
				if err != nil {
					return
				}
			}
		}
	}
	return
}

func (t *Template) byteIsWhitespace(r byte) bool {
	switch r {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

type DirectiveDefinition struct {
	Name    []byte
	Resolve func(w io.Writer, arg []byte) (n int, err error)
}

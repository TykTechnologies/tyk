package ast

import (
	"io"
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/runes"
)

type Description struct {
	IsDefined     bool
	IsBlockString bool               // true if -> """content""" ; else "content"
	Content       ByteSliceReference // literal
	Position      position.Position
}

// nolint
func (d *Document) PrintDescription(description Description, indent []byte, depth int, writer io.Writer) (err error) {
	for i := 0; i < depth; i++ {
		_, err = writer.Write(indent)
	}
	if description.IsBlockString {
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.LINETERMINATOR)
		for i := 0; i < depth; i++ {
			_, err = writer.Write(indent)
		}
	} else {
		_, err = writer.Write(literal.QUOTE)
	}

	content := d.Input.ByteSlice(description.Content)
	skipWhitespace := false
	for i := range content {
		switch content[i] {
		case runes.LINETERMINATOR:
			skipWhitespace = true
		case runes.TAB, runes.SPACE:
			if skipWhitespace {
				continue
			}
		default:
			if skipWhitespace {
				for i := 0; i < depth; i++ {
					_, err = writer.Write(indent)
				}
			}
			skipWhitespace = false
		}
		_, err = writer.Write(content[i : i+1])
	}
	if description.IsBlockString {
		_, err = writer.Write(literal.LINETERMINATOR)
		for i := 0; i < depth; i++ {
			_, err = writer.Write(indent)
		}
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
		_, err = writer.Write(literal.QUOTE)
	} else {
		_, err = writer.Write(literal.QUOTE)
	}
	return nil
}

func (d *Document) ImportDescription(desc string) (description Description) {
	if desc == "" {
		return
	}

	return Description{
		IsDefined:     true,
		IsBlockString: strings.Contains(desc, "\n"),
		Content:       d.Input.AppendInputString(desc),
	}
}

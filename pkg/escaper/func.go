package escaper

import (
	"fmt"
)

var jsonMappings map[rune]string

// nolint:gochecknoinits
func init() {
	jsonMappings = map[rune]string{
		'"': `\x22`,
		// '\'': `\x27`, <- skipped
		'&':      `\u0026`,
		'<':      `\u003C`,
		'>':      `\u003E`,
		'\\':     `\\`,
		'\n':     `\n`,
		'\r':     `\r`,
		'\t':     `\t`,
		'\u2028': `\u2028`, // Line Separator as in html/template
		'\u2029': `\u2029`, // Paragraph Separator as in html/template
	}

	for i := rune(0); i < 32; i++ {
		if i == '\n' || i == '\r' || i == '\t' {
			continue
		}
		jsonMappings[i] = fmt.Sprintf(`\u%04X`, i)
	}
}

var jsonEscaper = New(jsonMappings)

func JsonEscapeString(s string) string {
	return jsonEscaper.Escape(s)
}

package escaper

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	jsLowUni    = `\u00`
	hex         = "0123456789ABCDEF"
	jsBackslash = `\\`
	jsQuot      = `\"`
	jsLt        = `\u003C`
	jsGt        = `\u003E`
	jsAmp       = `\u0026`
	jsEq        = `\u003D`
)

func jsonIsSpecialCustom(r rune) bool {
	switch r {
	case '\\', '"', '<', '>', '&', '=':
		return true
	}
	return r < ' ' || utf8.RuneSelf <= r
}

// JsonEscapeString
// this function is fork of https://pkg.go.dev/text/template#JSEscapeString
// created on purpose to fix the bug https://tyktech.atlassian.net/browse/TT-14798
func JsonEscapeString(s string) string {
	if strings.IndexFunc(s, jsonIsSpecialCustom) < 0 {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 16)

	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]

		if !jsonIsSpecialCustom(rune(c)) {
			continue
		}

		b.WriteString(s[last:i])

		if c < utf8.RuneSelf {
			switch c {
			case '\\':
				b.WriteString(jsBackslash)
			case '"':
				b.WriteString(jsQuot)
			case '<':
				b.WriteString(jsLt)
			case '>':
				b.WriteString(jsGt)
			case '&':
				b.WriteString(jsAmp)
			case '=':
				b.WriteString(jsEq)
			default:
				// convertion ASCII control symbols (np. \n, \t) to the format \u00XX
				b.WriteString(jsLowUni)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0x0f])
			}
		} else {
			r, size := utf8.DecodeRuneInString(s[i:])
			if unicode.IsPrint(r) {
				b.WriteString(s[i : i+size])
			} else {
				fmt.Fprintf(&b, "\\u%04X", r)
			}
			i += size - 1
		}
		last = i + 1
	}

	b.WriteString(s[last:])
	return b.String()
}

package escaper

import "strings"

type Escaper struct {
	fastPath [256]string
	slowPath map[rune]string
	maxRune  rune
}

func New(mappings map[rune]string) *Escaper {
	e := &Escaper{
		slowPath: make(map[rune]string),
	}

	for k, v := range mappings {
		if k > e.maxRune {
			e.maxRune = k
		}

		if k < 256 {
			e.fastPath[k] = v
		} else {
			e.slowPath[k] = v
		}
	}

	return e
}

func (e *Escaper) Escape(s string) string {
	for _, r := range s {
		if r > e.maxRune {
			continue
		}

		if r < 256 {
			if e.fastPath[r] != "" {
				goto allocatePath
			}
		} else {
			if _, ok := e.slowPath[r]; ok {
				goto allocatePath
			}
		}
	}

	return s

allocatePath:
	var b strings.Builder
	b.Grow(len(s) + 16)

	for _, r := range s {
		if r < 256 {
			if replacement := e.fastPath[r]; replacement != "" {
				b.WriteString(replacement)
			} else {
				b.WriteRune(r)
			}
		} else {
			if replacement, ok := e.slowPath[r]; ok {
				b.WriteString(replacement)
			} else {
				b.WriteRune(r)
			}
		}
	}

	return b.String()
}

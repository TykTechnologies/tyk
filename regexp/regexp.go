/*
Package regexp implmenets API of Go's native "regexp" but with caching results in memory
*/
package regexp

import (
	"io"
	"regexp"
	"strconv"
)

var (
	compileRegexpCache                 = compileCache{}
	compileRegexpPOSIXCache            = compilePOSIXCache{}
	matchStringRegexpCache             = matchStringCache{}
	matchRegexpCache                   = matchCache{}
	replaceAllStringRegexpCache        = replaceAllStringCache{}
	replaceAllLiteralStringRegexpCache = replaceAllLiteralStringCache{}
	replaceAllStringFuncRegexpCache    = replaceAllStringFuncCache{}
)

// Regexp is a wrapper around regexp.Regexp but with caching
type Regexp struct {
	*regexp.Regexp
	FromCache bool
}

func init() {
	ResetCache()
}

// ResetCache resets cache to initial state
func ResetCache() {
	compileRegexpCache.reset()
	compileRegexpPOSIXCache.reset()
	matchStringRegexpCache.reset()
	matchRegexpCache.reset()
	replaceAllStringRegexpCache.reset()
	replaceAllLiteralStringRegexpCache.reset()
	replaceAllStringFuncRegexpCache.reset()
}

// Compile does the same as regexp.Compile but returns cached *Regexp instead.
func Compile(expr string) (*Regexp, error) {
	return compileRegexpCache.compile(expr)
}

// CompilePOSIX does the same as regexp.CompilePOSIX but returns cached *Regexp instead.
func CompilePOSIX(expr string) (*Regexp, error) {
	return compileRegexpPOSIXCache.compilePOSIX(expr)
}

// MustCompile is the same as regexp.MustCompile but returns cached *Regexp instead.
func MustCompile(str string) *Regexp {
	regexp, err := Compile(str)
	if err != nil {
		panic(`regexp: Compile(` + quote(str) + `): ` + err.Error())
	}
	return regexp
}

// MustCompilePOSIX is the same as regexp.MustCompilePOSIX but returns cached *Regexp instead.
func MustCompilePOSIX(str string) *Regexp {
	regexp, err := CompilePOSIX(str)
	if err != nil {
		panic(`regexp: CompilePOSIX(` + quote(str) + `): ` + err.Error())
	}
	return regexp
}

// MatchString is the same as regexp.MatchString but returns cached result instead.
func MatchString(pattern string, s string) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// Match is the same as regexp.Match but returns cached result instead.
func Match(pattern string, b []byte) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.Match(b), nil
}

// QuoteMeta is the same as regexp.QuoteMeta but returns cached result instead.
func QuoteMeta(s string) string {
	// TODO: add cache for QuoteMeta
	return regexp.QuoteMeta(s)
}

func quote(s string) string {
	if strconv.CanBackquote(s) {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

// String returns the source text used to compile the wrapped regular expression.
func (re *Regexp) String() string {
	if re.Regexp == nil {
		return ""
	}
	return re.Regexp.String()
}

// Copy returns a new Regexp object copied from re.
//
// When using a Regexp in multiple goroutines, giving each goroutine
// its own copy helps to avoid lock contention.
func (re *Regexp) Copy() *Regexp {
	return &Regexp{
		re.Regexp.Copy(),
		re.FromCache,
	}
}

// Longest calls regexp.Regexp.Longest of wrapped regular expression
func (re *Regexp) Longest() {
	if re.Regexp == nil {
		re.Regexp.Longest()
	}
}

// NumSubexp returns result of regexp.Regexp.NumSubexp of wrapped regular expression.
func (re *Regexp) NumSubexp() int {
	if re.Regexp == nil {
		return 0
	}
	return re.Regexp.NumSubexp()
}

// SubexpNames returns result of regexp.Regexp.SubexpNames of wrapped regular expression.
func (re *Regexp) SubexpNames() []string {
	if re.Regexp == nil {
		return []string{}
	}
	return re.Regexp.SubexpNames()
}

// LiteralPrefix returns a literal string that must begin any match
// Calls regexp.Regexp.LiteralPrefix
func (re *Regexp) LiteralPrefix() (prefix string, complete bool) {
	if re.Regexp == nil {
		return "", false
	}
	return re.Regexp.LiteralPrefix()
}

// MatchReader reports whether the Regexp matches the text read by the
// RuneReader.
// Calls regexp.Regexp.MatchReader (NO CACHE)
func (re *Regexp) MatchReader(r io.RuneReader) bool {
	if re.Regexp == nil {
		return false
	}
	return re.Regexp.MatchReader(r)
}

// MatchString reports whether the Regexp matches the string s.
func (re *Regexp) MatchString(s string) bool {
	if re.Regexp == nil {
		return false
	}
	return matchStringRegexpCache.matchString(re.Regexp, s)
}

// Match reports whether the Regexp matches the byte slice b.
func (re *Regexp) Match(b []byte) bool {
	if re.Regexp == nil {
		return false
	}
	return matchRegexpCache.match(re.Regexp, b)
}

// ReplaceAllString is the same as regexp.Regexp.ReplaceAllString but returns cached result instead.
func (re *Regexp) ReplaceAllString(src, repl string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllStringRegexpCache.replaceAllString(re.Regexp, src, repl)
}

// ReplaceAllLiteralString is the same as regexp.Regexp.ReplaceAllLiteralString but returns cached result instead.
func (re *Regexp) ReplaceAllLiteralString(src, repl string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllLiteralStringRegexpCache.replaceAllLiteralString(re.Regexp, src, repl)
}

// ReplaceAllStringFunc is the same as regexp.Regexp.ReplaceAllStringFunc but returns cached result instead.
func (re *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllStringFuncRegexpCache.replaceAllStringFunc(re.Regexp, src, repl)
}

// ReplaceAll is the same as regexp.Regexp.ReplaceAll but returns cached result instead.
func (re *Regexp) ReplaceAll(src, repl []byte) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for ReplaceAll
	return re.Regexp.ReplaceAll(src, repl)
}

// ReplaceAllLiteral is the same as regexp.Regexp.ReplaceAllLiteral but returns cached result instead.
func (re *Regexp) ReplaceAllLiteral(src, repl []byte) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for ReplaceAllLiteral
	return re.Regexp.ReplaceAllLiteral(src, repl)
}

// ReplaceAllFunc is the same as regexp.Regexp.ReplaceAllFunc but returns cached result instead.
func (re *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for ReplaceAllFunc
	return re.Regexp.ReplaceAllFunc(src, repl)
}

// Find is the same as regexp.Regexp.Find but returns cached result instead.
func (re *Regexp) Find(b []byte) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for Find
	return re.Regexp.Find(b)
}

// FindIndex is the same as regexp.Regexp.FindIndex but returns cached result instead.
func (re *Regexp) FindIndex(b []byte) (loc []int) {
	if re.Regexp == nil {
		return
	}
	// TODO: add cache for FindIndex
	return re.Regexp.FindIndex(b)
}

// FindString is the same as regexp.Regexp.FindString but returns cached result instead.
func (re *Regexp) FindString(s string) string {
	if re.Regexp == nil {
		return ""
	}
	// TODO: add cache for FindString
	return re.Regexp.FindString(s)
}

// FindStringIndex is the same as regexp.Regexp.FindStringIndex but returns cached result instead.
func (re *Regexp) FindStringIndex(s string) (loc []int) {
	if re.Regexp == nil {
		return
	}
	// TODO: add cache for FindStringIndex
	return re.Regexp.FindStringIndex(s)
}

// FindReaderIndex is the same as regexp.Regexp.FindReaderIndex (NO CACHE).
func (re *Regexp) FindReaderIndex(r io.RuneReader) (loc []int) {
	if re.Regexp == nil {
		return
	}
	return re.Regexp.FindReaderIndex(r)
}

// FindSubmatch is the same as regexp.Regexp.FindSubmatch but returns cached result instead.
func (re *Regexp) FindSubmatch(b []byte) [][]byte {
	if re.Regexp == nil {
		return [][]byte{}
	}
	// TODO: add cache for FindSubmatch
	return re.Regexp.FindSubmatch(b)
}

// Expand is the same as regexp.Regexp.Expand but returns cached result instead.
func (re *Regexp) Expand(dst []byte, template []byte, src []byte, match []int) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for Expand
	return re.Regexp.Expand(dst, template, src, match)
}

// ExpandString is the same as regexp.Regexp.ExpandString but returns cached result instead.
func (re *Regexp) ExpandString(dst []byte, template string, src string, match []int) []byte {
	if re.Regexp == nil {
		return []byte{}
	}
	// TODO: add cache for ExpandString
	return re.Regexp.ExpandString(dst, template, src, match)
}

// FindSubmatchIndex is the same as regexp.Regexp.FindSubmatchIndex but returns cached result instead.
func (re *Regexp) FindSubmatchIndex(b []byte) []int {
	if re.Regexp == nil {
		return []int{}
	}
	// TODO: add cache for ExpandString
	return re.Regexp.FindSubmatchIndex(b)
}

// FindStringSubmatch is the same as regexp.Regexp.FindStringSubmatch but returns cached result instead.
func (re *Regexp) FindStringSubmatch(s string) []string {
	if re.Regexp == nil {
		return []string{}
	}
	// TODO: add cache for FindStringSubmatch
	return re.Regexp.FindStringSubmatch(s)
}

// FindStringSubmatchIndex is the same as regexp.Regexp.FindStringSubmatchIndex but returns cached result instead.
func (re *Regexp) FindStringSubmatchIndex(s string) []int {
	if re.Regexp == nil {
		return []int{}
	}
	// TODO: add cache for FindStringSubmatchIndex
	return re.Regexp.FindStringSubmatchIndex(s)
}

// FindReaderSubmatchIndex is the same as regexp.Regexp.FindReaderSubmatchIndex (NO CACHE).
func (re *Regexp) FindReaderSubmatchIndex(r io.RuneReader) []int {
	if re.Regexp == nil {
		return []int{}
	}
	return re.Regexp.FindReaderSubmatchIndex(r)
}

// FindAll is the same as regexp.Regexp.FindAll but returns cached result instead.
func (re *Regexp) FindAll(b []byte, n int) [][]byte {
	if re.Regexp == nil {
		return [][]byte{}
	}
	// TODO: add cache for FindAll
	return re.Regexp.FindAll(b, n)
}

// FindAllIndex is the same as regexp.Regexp.FindAllIndex but returns cached result instead.
func (re *Regexp) FindAllIndex(b []byte, n int) [][]int {
	if re.Regexp == nil {
		return [][]int{}
	}
	// TODO: add cache for FindAllIndex
	return re.Regexp.FindAllIndex(b, n)
}

// FindAllString is the same as regexp.Regexp.FindAllString but returns cached result instead.
func (re *Regexp) FindAllString(s string, n int) []string {
	if re.Regexp == nil {
		return []string{}
	}
	// TODO: add cache for FindAllString
	return re.Regexp.FindAllString(s, n)
}

// FindAllStringIndex is the same as regexp.Regexp.FindAllStringIndex but returns cached result instead.
func (re *Regexp) FindAllStringIndex(s string, n int) [][]int {
	if re.Regexp == nil {
		return [][]int{}
	}
	// TODO: add cache for FindAllStringIndex
	return re.Regexp.FindAllStringIndex(s, n)
}

// FindAllSubmatch is the same as regexp.Regexp.FindAllSubmatch but returns cached result instead.
func (re *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	if re.Regexp == nil {
		return [][][]byte{}
	}
	// TODO: add cache for FindAllSubmatch
	return re.Regexp.FindAllSubmatch(b, n)
}

// FindAllSubmatchIndex is the same as regexp.Regexp.FindAllSubmatchIndex but returns cached result instead.
func (re *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	if re.Regexp == nil {
		return [][]int{}
	}
	// TODO: add cache for FindAllSubmatchIndex
	return re.Regexp.FindAllSubmatchIndex(b, n)
}

// FindAllStringSubmatch is the same as regexp.Regexp.FindAllStringSubmatch but returns cached result instead.
func (re *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	if re.Regexp == nil {
		return [][]string{}
	}
	// TODO: add cache for FindAllStringSubmatch
	return re.Regexp.FindAllStringSubmatch(s, n)
}

// FindAllStringSubmatchIndex is the same as regexp.Regexp.FindAllStringSubmatchIndex but returns cached result instead.
func (re *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if re.Regexp == nil {
		return [][]int{}
	}
	// TODO: add cache for FindAllStringSubmatchIndex
	return re.Regexp.FindAllStringSubmatchIndex(s, n)
}

// Split is the same as regexp.Regexp.Split but returns cached result instead.
func (re *Regexp) Split(s string, n int) []string {
	if re.Regexp == nil {
		return []string{}
	}
	// TODO: add cache for Split
	return re.Regexp.Split(s, n)
}

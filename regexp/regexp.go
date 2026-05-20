// Package regexp wraps Go's standard "regexp" with a process-wide
// bounded LRU. Intended for Tyk gateway internals.
//
// The cached *regexp.Regexp is shared across all callers and MUST NOT
// be mutated. Read-only methods (Match*, Find*, ReplaceAll*, String,
// NumSubexp, SubexpNames, LiteralPrefix) are safe for concurrent use
// since Go 1.12.
//
// External consumers (Tyk plugins, sibling repos) should use the
// standard library regexp package directly unless they specifically
// need to share Tyk's gateway-wide compile cache.
package regexp

import (
	"io"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	internalcache "github.com/TykTechnologies/tyk/internal/cache"
)

const defaultCacheTTL = 60 * time.Second

// LogFunc aliases the shared LRU eviction LogFunc.
type LogFunc = internalcache.LogFunc

// CacheOptions aliases internalcache.LRUOptions; kept as the public type
// for code already wired against this package.
type CacheOptions = internalcache.LRUOptions

var (
	compileCache                 atomic.Pointer[regexpCache]
	compilePOSIXCache            atomic.Pointer[regexpCache]
	matchStringCache             atomic.Pointer[regexpStrRetBoolCache]
	matchCache                   atomic.Pointer[regexpByteRetBoolCache]
	replaceAllStringCache        atomic.Pointer[regexpStrStrRetStrCache]
	replaceAllLiteralStringCache atomic.Pointer[regexpStrStrRetStrCache]
	replaceAllStringFuncCache    atomic.Pointer[regexpStrFuncRetStrCache]
	findStringSubmatchCache      atomic.Pointer[regexpStrRetSliceStrCache]
	findAllStringCache           atomic.Pointer[regexpStrIntRetSliceStrCache]
	findAllStringSubmatchCache   atomic.Pointer[regexpStrIntRetSliceSliceStrCache]
)

func init() {
	applyCacheConfig(CacheOptions{Enabled: true})
}

// Configure (re)builds the package-level caches from opts. Intended for
// one-shot gateway startup wiring; safe to call again from tests.
func Configure(opts CacheOptions) {
	applyCacheConfig(opts)
}

// CompileCacheLen returns the current entry count of the compile cache.
// Intended for tests that need to assert eviction behavior.
func CompileCacheLen() int {
	if c := compileCache.Load(); c != nil {
		return c.lru.Len()
	}
	return 0
}

// Reset toggles the cache-enabled flag and purges all entries. Bounds
// (TTL/MaxEntries) are fixed at Configure time and not affected here.
func Reset(isEnabled bool) {
	compileCache.Load().reset(isEnabled)
	compilePOSIXCache.Load().reset(isEnabled)
	matchStringCache.Load().reset(isEnabled)
	matchCache.Load().reset(isEnabled)
	replaceAllStringCache.Load().reset(isEnabled)
	replaceAllLiteralStringCache.Load().reset(isEnabled)
	replaceAllStringFuncCache.Load().reset(isEnabled)
	findStringSubmatchCache.Load().reset(isEnabled)
	findAllStringCache.Load().reset(isEnabled)
	findAllStringSubmatchCache.Load().reset(isEnabled)
}

// ResetCache is the pre-TT-17049 entry point. Kept as a thin shim so
// out-of-tree callers (plugins, sibling repos) keep compiling; ttl is
// now fixed at Configure time and the argument is ignored.
//
// Deprecated: use Reset(isEnabled).
func ResetCache(_ time.Duration, isEnabled bool) {
	Reset(isEnabled)
}

// prevReporter tracks the last EvictionLogger so its goroutine can be
// stopped when applyCacheConfig is called again.
var prevReporter atomic.Pointer[internalcache.EvictionLogger]

// applyCacheConfig (re)builds all package caches and, if opts.Log is set,
// starts the eviction-summary ticker.
func applyCacheConfig(opts CacheOptions) {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	maxEntries := internalcache.ResolveMaxEntries(opts)

	if old := prevReporter.Swap(nil); old != nil {
		old.Stop()
	}

	rep := internalcache.NewEvictionLogger("regex cache", opts.Log)

	compileCache.Store(newRegexpCache(ttl, maxEntries, opts.Enabled, "compile", rep, regexp.Compile))
	compilePOSIXCache.Store(newRegexpCache(ttl, maxEntries, opts.Enabled, "compilePOSIX", rep, regexp.CompilePOSIX))
	matchStringCache.Store(newRegexpStrRetBoolCache(ttl, maxEntries, opts.Enabled, "matchString", rep))
	matchCache.Store(newRegexpByteRetBoolCache(ttl, maxEntries, opts.Enabled, "match", rep))
	replaceAllStringCache.Store(newRegexpStrStrRetStrCache(ttl, maxEntries, opts.Enabled, "replaceAllString", rep))
	replaceAllLiteralStringCache.Store(newRegexpStrStrRetStrCache(ttl, maxEntries, opts.Enabled, "replaceAllLiteralString", rep))
	replaceAllStringFuncCache.Store(newRegexpStrFuncRetStrCache(ttl, maxEntries, opts.Enabled, "replaceAllStringFunc", rep))
	findStringSubmatchCache.Store(newRegexpStrRetSliceStrCache(ttl, maxEntries, opts.Enabled, "findStringSubmatch", rep))
	findAllStringCache.Store(newRegexpStrIntRetSliceStrCache(ttl, maxEntries, opts.Enabled, "findAllString", rep))
	findAllStringSubmatchCache.Store(newRegexpStrIntRetSliceSliceStrCache(ttl, maxEntries, opts.Enabled, "findAllStringSubmatch", rep))

	if opts.Log != nil {
		rep.Start(internalcache.DefaultEvictionLogInterval)
		prevReporter.Store(rep)
	}
}

// Regexp is a wrapper around regexp.Regexp but with caching
type Regexp struct {
	*regexp.Regexp
	FromCache bool
}

// Compile does the same as regexp.Compile but returns cached *Regexp instead.
func Compile(expr string) (*Regexp, error) {
	return compileCache.Load().do(expr)
}

// CompilePOSIX does the same as regexp.CompilePOSIX but returns cached *Regexp instead.
func CompilePOSIX(expr string) (*Regexp, error) {
	return compilePOSIXCache.Load().do(expr)
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
	reCopy := &Regexp{
		FromCache: re.FromCache,
	}
	if re.Regexp != nil {
		reCopy.Regexp = re.Regexp.Copy()
	}
	return reCopy
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
	return matchStringCache.Load().do(re.Regexp, s, re.Regexp.MatchString)
}

// Match reports whether the Regexp matches the byte slice b.
func (re *Regexp) Match(b []byte) bool {
	if re.Regexp == nil {
		return false
	}
	return matchCache.Load().do(re.Regexp, b, re.Regexp.Match)
}

// ReplaceAllString is the same as regexp.Regexp.ReplaceAllString but returns cached result instead.
func (re *Regexp) ReplaceAllString(src, repl string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllStringCache.Load().do(re.Regexp, src, repl, re.Regexp.ReplaceAllString)
}

// ReplaceAllLiteralString is the same as regexp.Regexp.ReplaceAllLiteralString but returns cached result instead.
func (re *Regexp) ReplaceAllLiteralString(src, repl string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllLiteralStringCache.Load().do(re.Regexp, src, repl, re.Regexp.ReplaceAllLiteralString)
}

// ReplaceAllStringFunc is the same as regexp.Regexp.ReplaceAllStringFunc but returns cached result instead.
func (re *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	if re.Regexp == nil {
		return ""
	}
	return replaceAllStringFuncCache.Load().do(re.Regexp, src, repl, re.Regexp.ReplaceAllStringFunc)
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
	return findStringSubmatchCache.Load().do(re.Regexp, s, re.Regexp.FindStringSubmatch)
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
	return findAllStringCache.Load().do(re.Regexp, s, n, re.Regexp.FindAllString)
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
	return findAllStringSubmatchCache.Load().do(re.Regexp, s, n, re.Regexp.FindAllStringSubmatch)
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

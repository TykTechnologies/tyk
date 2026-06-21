package regexp

import (
	"reflect"
	"strings"
	"testing"
)

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// STK-REQ-068:STK-REQ-068-AC-01:acceptance
// MCDC SYS-REQ-156: regexp_cache_operation_terminal=T => TRUE
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
//
//mcdc:ignore SYS-REQ-156: regexp_cache_operation_terminal=F => FALSE -- the onboarded regexp cache operations are synchronous local helpers that either compile or reuse a regexp, delegate to the Go regexp implementation, return nil-wrapper defaults, return an invalid-pattern error or panic, or bypass cache storage for disabled or oversized cache cases before returning; a non-terminal local result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestCompile(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx, err := Compile("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if rx.FromCache {
		t.Error("Regexp shoul not be from cache")
	}
	if !rx.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx.String())
	}
	// 2nd hit
	rx2, err := Compile("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if !rx2.FromCache {
		t.Error("Regexp shoul be from cache")
	}
	if !rx2.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx2.String())
	}
}

func BenchmarkRegExpCompile(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)

	b.ReportAllocs()

	var rx *Regexp
	var err error

	for i := 0; i < b.N; i++ {
		rx, err = Compile("^abc.*$")
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Log(rx)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestCompilePOSIX(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx, err := CompilePOSIX("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if rx.FromCache {
		t.Error("Regexp shoul not be from cache")
	}
	if !rx.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx.String())
	}
	// 2nd hit
	rx2, err := CompilePOSIX("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if !rx2.FromCache {
		t.Error("Regexp shoul be from cache")
	}
	if !rx2.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx2.String())
	}
}

func BenchmarkRegExpCompilePOSIX(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)

	b.ReportAllocs()

	var rx *Regexp
	var err error

	for i := 0; i < b.N; i++ {
		rx, err = CompilePOSIX("^abc.*$")
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Log(rx)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SYS-REQ-156:error_handling:nominal
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:error_handling:nominal
// SW-REQ-143:error_handling:negative
// SW-REQ-143:determinism:nominal
func TestMustCompile(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx := MustCompile("^abc.*$")
	if rx.FromCache {
		t.Error("Regexp shoul not be from cache")
	}
	if !rx.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx.String())
	}
	// 2nd hit
	rx2 := MustCompile("^abc.*$")
	if !rx2.FromCache {
		t.Error("Regexp shoul be from cache")
	}
	if !rx2.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx2.String())
	}
	// catch panic
	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		MustCompile("*")
	}()
	if !panicked {
		t.Error("Expected panic but it didn't happen")
	}
}

func BenchmarkRegExpMustCompile(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)

	b.ReportAllocs()

	var rx *Regexp

	for i := 0; i < b.N; i++ {
		rx = MustCompile("^abc.*$")
	}

	b.Log(rx)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:error_handling:negative
// SW-REQ-143:determinism:nominal
func TestMustCompilePOSIX(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx := MustCompilePOSIX("^abc.*$")
	if rx.FromCache {
		t.Error("Regexp shoul not be from cache")
	}
	if !rx.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx.String())
	}
	// 2nd hit
	rx2 := MustCompilePOSIX("^abc.*$")
	if !rx2.FromCache {
		t.Error("Regexp shoul be from cache")
	}
	if !rx2.MatchString("abcxyz") {
		t.Error("String didn't match to compiled regexp: ", rx2.String())
	}
	// catch panic
	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		MustCompilePOSIX("*")
	}()
	if !panicked {
		t.Error("Expected panic but it didn't happen")
	}
}

func BenchmarkRegExpMustCompilePOSIX(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)
	b.ReportAllocs()

	var rx *Regexp

	for i := 0; i < b.N; i++ {
		rx = MustCompilePOSIX("^abc.*$")
	}

	b.Log(rx)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestMatchString(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	matched, err := MatchString("^abc.*$", "abcedfxyz")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("String didn't match")
	}
	// 2nd hit
	matched, err = MatchString("^abc.*$", "abcedfxyz")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("String didn't match")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// STK-REQ-068:error_handling:negative
// SYS-REQ-156:error_handling:negative
// SW-REQ-143:error_handling:negative
func TestMatchStringFailed(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	_, err := MatchString("*", "abcedfxyz")
	if err == nil {
		t.Error("Expected error")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestMatchStringRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	rx := Regexp{}
	matched := rx.MatchString("abcdefxyz")
	if matched {
		t.Error("Expected not to match")
	}
}

func BenchmarkRegExpMatchString(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)
	b.ReportAllocs()

	matched := false
	var err error

	for i := 0; i < b.N; i++ {
		matched, err = MatchString("^abc.*$", "abcdefxyz")
		if err != nil {
			b.Fatal(err)
		}
		if !matched {
			b.Error("String didn't match")
		}
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestMatch(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	data := []byte("abcdefxyz")
	// 1st miss
	matched, err := Match("^abc.*$", data)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("String didn't match")
	}
	// 2nd hit
	matched, err = Match("^abc.*$", data)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("String didn't match")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:error_handling:negative
func TestMatchFailed(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	_, err := Match("*", []byte("abcdefxyz"))
	if err == nil {
		t.Error("Expected error")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestMatchRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	rx := Regexp{}
	matched := rx.Match([]byte("abcdefxyz"))
	if matched {
		t.Error("Expected not to match")
	}
}

func BenchmarkRegExpMatch(b *testing.B) {
	ResetCache(defaultCacheItemTTL, true)

	b.ReportAllocs()

	data := []byte("abcdefxyz")

	matched := false
	var err error

	for i := 0; i < b.N; i++ {
		matched, err = Match("^abc.*$", data)
		if err != nil {
			b.Fatal(err)
		}
		if !matched {
			b.Error("Data didn't match")
		}
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:determinism:nominal
func TestString(t *testing.T) {
	rx, err := Compile("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if rx.String() != "^abc.*$" {
		t.Error("String didn't match to compiled regexp expression")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestStringRegexpNotSet(t *testing.T) {
	rx := Regexp{}
	if rx.String() != "" {
		t.Error("Empty string expected")
	}
}

func BenchmarkRegExpString(b *testing.B) {
	b.ReportAllocs()

	rx, err := Compile("^abc.*$")
	if err != nil {
		b.Fatal(err)
	}
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.String()
	}

	b.Log(str)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:determinism:nominal
func TestCopy(t *testing.T) {
	rx, err := Compile("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	rxCopy := rx.Copy()
	if rx.FromCache != rxCopy.FromCache {
		t.Error("Copy's FromCache is not equal")
	}
	if rx.String() != rxCopy.String() {
		t.Error("Copy's Regexp is not equal")
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllString(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr2 != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllStringRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	rx := &Regexp{}
	newStr := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr != "" {
		t.Error("Expected empty string")
	}
}

func BenchmarkRegexpReplaceAllString(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	rx := MustCompile("abc")
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.ReplaceAllString("qweabcxyz", "123")
	}

	b.Log(str)

}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllLiteralString(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr2 != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllLiteralStringRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)
	rx := &Regexp{}
	newStr := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr != "" {
		t.Error("Expected empty string")
	}
}

func BenchmarkRegexpReplaceAllLiteralString(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	rx := MustCompile("abc")
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.ReplaceAllLiteralString("qweabcxyz", "123")
	}

	b.Log(str)

}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllStringFunc(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	f := func(s string) string {
		return strings.ToUpper(s)
	}

	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr != "qweABCxyz" {
		t.Error("Expected 'qweABCxyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr2 != "qweABCxyz" {
		t.Error("Expected 'qweABCxyz'. Got:", newStr2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestReplaceAllStringFuncRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	f := func(s string) string {
		return strings.ToUpper(s)
	}

	rx := &Regexp{}
	newStr := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr != "" {
		t.Error("Expected empty string returned")
	}
}

func BenchmarkRegexpReplaceAllStringFunc(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	f := func(s string) string {
		return strings.ToUpper(s)
	}

	rx := MustCompile("abc")
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.ReplaceAllStringFunc("qweabcxyz", f)
	}

	b.Log(str)

}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestFindAllString(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	// 1st miss
	rx := MustCompile("abc")
	res := rx.FindAllString("qweabcxyzabc123abcz", -1)
	expectedRes := []string{"abc", "abc", "abc"}
	if !reflect.DeepEqual(res, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res)
	}
	// 2nd hit
	res2 := rx.FindAllString("qweabcxyzabc123abcz", -1)
	if !reflect.DeepEqual(res2, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestFindAllStringRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	rx := &Regexp{}

	res := rx.FindAllString("qweabcxyzabc123abcz", -1)
	if len(res) > 0 {
		t.Error("Expected 0 length slice returned. Got:", res)
	}
}

func BenchmarkRegexpFindAllString(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	rx := MustCompile("abc")
	var res []string

	for i := 0; i < b.N; i++ {
		res = rx.FindAllString("qweabcxyzabc123abcz", -1)
	}

	b.Log(res)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestFindAllStringSubmatch(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	// 1st miss
	rx := MustCompile("abc")
	res := rx.FindAllStringSubmatch("qweabcxyzabc123abcz", -1)
	expectedRes := [][]string{
		{"abc"},
		{"abc"},
		{"abc"},
	}
	if !reflect.DeepEqual(res, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res)
	}
	// 2nd hit
	res2 := rx.FindAllStringSubmatch("qweabcxyzabc123abcz", -1)
	if !reflect.DeepEqual(res2, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestTestFindAllStringSubmatchRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	rx := &Regexp{}

	res := rx.FindAllStringSubmatch("qweabcxyzabc123abcz", -1)
	if len(res) > 0 {
		t.Error("Expected 0 length slice returned. Got:", res)
	}
}

func BenchmarkRegexpFindAllStringSubmatch(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	rx := MustCompile("abc")
	var res [][]string

	for i := 0; i < b.N; i++ {
		res = rx.FindAllStringSubmatch("qweabcxyzabc123abcz", -1)
	}

	b.Log(res)
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestFindStringSubmatch(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	// 1st miss
	rx := MustCompile("abc(\\w)")
	res := rx.FindStringSubmatch("qweabcxyzabc123abcz")
	expectedRes := []string{"abcx", "x"}

	if !reflect.DeepEqual(res, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res)
	}
	// 2nd hit
	res2 := rx.FindStringSubmatch("qweabcxyzabc123abcz")
	if !reflect.DeepEqual(res2, expectedRes) {
		t.Error("Expected :", expectedRes, " Got:", res2)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestTestFindStringSubmatchRegexpNotSet(t *testing.T) {
	ResetCache(defaultCacheItemTTL, true)

	rx := &Regexp{}

	res := rx.FindStringSubmatch("qweabcxyzabc123abcz")
	if len(res) > 0 {
		t.Error("Expected 0 length slice returned. Got:", res)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestQuoteMetaAndQuote(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"quote meta", QuoteMeta(`a+b?`), `a\+b\?`},
		{"backquote-safe", quote("abc"), "`abc`"},
		{"quoted newline", quote("a\nb"), `"a\nb"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestRegexpMetadataReaderAndLongest(t *testing.T) {
	t.Run("metadata and reader methods delegate to regexp", func(t *testing.T) {
		rx := MustCompile(`(?P<word>abc)(\d+)`)

		if got := rx.NumSubexp(); got != 2 {
			t.Fatalf("NumSubexp got %d, want 2", got)
		}
		if got, want := rx.SubexpNames(), []string{"", "word", ""}; !reflect.DeepEqual(got, want) {
			t.Fatalf("SubexpNames got %#v, want %#v", got, want)
		}
		if !rx.MatchReader(strings.NewReader("xxabc123")) {
			t.Fatal("MatchReader should match")
		}
		if got := rx.FindReaderIndex(strings.NewReader("xxabc123")); !reflect.DeepEqual(got, []int{2, 8}) {
			t.Fatalf("FindReaderIndex got %#v", got)
		}
		if got := rx.FindReaderSubmatchIndex(strings.NewReader("xxabc123")); !reflect.DeepEqual(got, []int{2, 8, 2, 5, 5, 8}) {
			t.Fatalf("FindReaderSubmatchIndex got %#v", got)
		}

		prefix, complete := MustCompile(`abc.*`).LiteralPrefix()
		if prefix != "abc" || complete {
			t.Fatalf("LiteralPrefix got (%q, %v), want (abc, false)", prefix, complete)
		}
	})

	t.Run("Longest applies to real regexp and is safe on nil wrapper", func(t *testing.T) {
		rx := MustCompile(`a(|b)`)
		if got := rx.FindString("ab"); got != "a" {
			t.Fatalf("before Longest got %q, want a", got)
		}

		rx.Longest()
		if got := rx.FindString("ab"); got != "ab" {
			t.Fatalf("after Longest got %q, want ab", got)
		}

		(&Regexp{}).Longest()
	})
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestRegexpByteAndIndexWrappers(t *testing.T) {
	rx := MustCompile(`a(\d)`)
	src := []byte("za1 ya2")

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"ReplaceAll", string(rx.ReplaceAll(src, []byte("x"))), "zx yx"},
		{"ReplaceAllLiteral", string(rx.ReplaceAllLiteral(src, []byte("$1"))), "z$1 y$1"},
		{"ReplaceAllFunc", string(rx.ReplaceAllFunc(src, func(b []byte) []byte { return []byte(strings.ToUpper(string(b))) })), "zA1 yA2"},
		{"Find", string(rx.Find(src)), "a1"},
		{"FindIndex", rx.FindIndex(src), []int{1, 3}},
		{"FindString", rx.FindString("za1 ya2"), "a1"},
		{"FindStringIndex", rx.FindStringIndex("za1 ya2"), []int{1, 3}},
		{"FindSubmatch", stringifyBytes(rx.FindSubmatch(src)), []string{"a1", "1"}},
		{"FindSubmatchIndex", rx.FindSubmatchIndex(src), []int{1, 3, 2, 3}},
		{"FindStringSubmatchIndex", rx.FindStringSubmatchIndex("za1 ya2"), []int{1, 3, 2, 3}},
		{"FindAll", stringifyByteSlices(rx.FindAll(src, -1)), []string{"a1", "a2"}},
		{"FindAllIndex", rx.FindAllIndex(src, -1), [][]int{{1, 3}, {5, 7}}},
		{"FindAllStringIndex", rx.FindAllStringIndex("za1 ya2", -1), [][]int{{1, 3}, {5, 7}}},
		{"FindAllSubmatch", stringifyByteSliceSlices(rx.FindAllSubmatch(src, -1)), [][]string{{"a1", "1"}, {"a2", "2"}}},
		{"FindAllSubmatchIndex", rx.FindAllSubmatchIndex(src, -1), [][]int{{1, 3, 2, 3}, {5, 7, 6, 7}}},
		{"FindAllStringSubmatchIndex", rx.FindAllStringSubmatchIndex("za1 ya2", -1), [][]int{{1, 3, 2, 3}, {5, 7, 6, 7}}},
		{"Split", rx.Split("za1 ya2", -1), []string{"z", " y", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Fatalf("got %#v, want %#v", tt.got, tt.want)
			}
		})
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestRegexpExpandWrappers(t *testing.T) {
	rx := MustCompile(`a(?P<num>\d+)`)

	byteSrc := []byte("a123")
	byteMatch := rx.FindSubmatchIndex(byteSrc)
	if got := string(rx.Expand(nil, []byte("num=$num"), byteSrc, byteMatch)); got != "num=123" {
		t.Fatalf("Expand got %q", got)
	}

	stringSrc := "a456"
	stringMatch := rx.FindStringSubmatchIndex(stringSrc)
	if got := string(rx.ExpandString(nil, "num=$num", stringSrc, stringMatch)); got != "num=456" {
		t.Fatalf("ExpandString got %q", got)
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestRegexpNilWrapperDefaults(t *testing.T) {
	rx := &Regexp{}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"NumSubexp", rx.NumSubexp(), 0},
		{"SubexpNames", rx.SubexpNames(), []string{}},
		{"LiteralPrefix", literalPrefixResult(rx), literalPrefix{prefix: "", complete: false}},
		{"MatchReader", rx.MatchReader(strings.NewReader("abc")), false},
		{"ReplaceAll", rx.ReplaceAll([]byte("abc"), []byte("x")), []byte{}},
		{"ReplaceAllLiteral", rx.ReplaceAllLiteral([]byte("abc"), []byte("x")), []byte{}},
		{"ReplaceAllFunc", rx.ReplaceAllFunc([]byte("abc"), func(b []byte) []byte { return b }), []byte{}},
		{"Find", rx.Find([]byte("abc")), []byte{}},
		{"FindIndex", rx.FindIndex([]byte("abc")), []int(nil)},
		{"FindString", rx.FindString("abc"), ""},
		{"FindStringIndex", rx.FindStringIndex("abc"), []int(nil)},
		{"FindReaderIndex", rx.FindReaderIndex(strings.NewReader("abc")), []int(nil)},
		{"FindSubmatch", rx.FindSubmatch([]byte("abc")), [][]byte{}},
		{"Expand", rx.Expand(nil, []byte("$0"), []byte("abc"), []int{0, 3}), []byte{}},
		{"ExpandString", rx.ExpandString(nil, "$0", "abc", []int{0, 3}), []byte{}},
		{"FindSubmatchIndex", rx.FindSubmatchIndex([]byte("abc")), []int{}},
		{"FindStringSubmatchIndex", rx.FindStringSubmatchIndex("abc"), []int{}},
		{"FindReaderSubmatchIndex", rx.FindReaderSubmatchIndex(strings.NewReader("abc")), []int{}},
		{"FindAll", rx.FindAll([]byte("abc"), -1), [][]byte{}},
		{"FindAllIndex", rx.FindAllIndex([]byte("abc"), -1), [][]int{}},
		{"FindAllStringIndex", rx.FindAllStringIndex("abc", -1), [][]int{}},
		{"FindAllSubmatch", rx.FindAllSubmatch([]byte("abc"), -1), [][][]byte{}},
		{"FindAllSubmatchIndex", rx.FindAllSubmatchIndex([]byte("abc"), -1), [][]int{}},
		{"FindAllStringSubmatchIndex", rx.FindAllStringSubmatchIndex("abc", -1), [][]int{}},
		{"Split", rx.Split("abc", -1), []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Fatalf("got %#v, want %#v", tt.got, tt.want)
			}
		})
	}
}

// Verifies: STK-REQ-068, SYS-REQ-156, SW-REQ-143
// SW-REQ-143:nominal:nominal
// SW-REQ-143:boundary:nominal
// SW-REQ-143:determinism:nominal
func TestRegexpCacheBoundaryBehavior(t *testing.T) {
	t.Run("ResetCache disables compile cache", func(t *testing.T) {
		ResetCache(defaultCacheItemTTL, false)
		first, err := Compile(`abc`)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Compile(`abc`)
		if err != nil {
			t.Fatal(err)
		}
		if first.FromCache || second.FromCache {
			t.Fatalf("disabled cache should not report cached results: first=%v second=%v", first.FromCache, second.FromCache)
		}
	})

	t.Run("zero TTL reset uses default cache TTL", func(t *testing.T) {
		ResetCache(0, true)
		if _, err := Compile(`abc`); err != nil {
			t.Fatal(err)
		}
		second, err := Compile(`abc`)
		if err != nil {
			t.Fatal(err)
		}
		if !second.FromCache {
			t.Fatal("zero TTL reset should keep caching enabled with the default TTL")
		}
	})

	t.Run("disabled and oversized cache paths execute directly", func(t *testing.T) {
		std := MustCompile(`a`).Regexp

		disabled := newRegexpStrRetBoolCache(defaultCacheItemTTL, false)
		disabledCalls := 0
		for i := 0; i < 2; i++ {
			disabled.do(std, "a", func(string) bool {
				disabledCalls++
				return true
			})
		}
		if disabledCalls != 2 {
			t.Fatalf("disabled cache calls = %d, want 2", disabledCalls)
		}

		oversizedKey := strings.Repeat("a", maxKeySize+1)
		keyLimited := newRegexpStrRetBoolCache(defaultCacheItemTTL, true)
		keyLimitedCalls := 0
		for i := 0; i < 2; i++ {
			keyLimited.do(std, oversizedKey, func(string) bool {
				keyLimitedCalls++
				return true
			})
		}
		if keyLimitedCalls != 2 {
			t.Fatalf("oversized-key calls = %d, want 2", keyLimitedCalls)
		}

		valueLimited := newRegexpStrStrRetStrCache(defaultCacheItemTTL, true)
		valueLimitedCalls := 0
		for i := 0; i < 2; i++ {
			valueLimited.do(std, "a", "b", func(string, string) string {
				valueLimitedCalls++
				return strings.Repeat("x", maxValueSize+1)
			})
		}
		if valueLimitedCalls != 2 {
			t.Fatalf("oversized-value calls = %d, want 2", valueLimitedCalls)
		}
	})
}

type literalPrefix struct {
	prefix   string
	complete bool
}

func literalPrefixResult(rx *Regexp) literalPrefix {
	prefix, complete := rx.LiteralPrefix()
	return literalPrefix{prefix: prefix, complete: complete}
}

func stringifyBytes(items [][]byte) []string {
	out := make([]string, len(items))
	for i := range items {
		out[i] = string(items[i])
	}
	return out
}

func stringifyByteSlices(items [][]byte) []string {
	return stringifyBytes(items)
}

func stringifyByteSliceSlices(items [][][]byte) [][]string {
	out := make([][]string, len(items))
	for i := range items {
		out[i] = stringifyBytes(items[i])
	}
	return out
}

func BenchmarkRegexpFindStringSubmatch(b *testing.B) {
	b.ReportAllocs()

	ResetCache(defaultCacheItemTTL, true)

	rx := MustCompile("abc(\\w)")
	var res []string

	for i := 0; i < b.N; i++ {
		res = rx.FindStringSubmatch("qweabcxyzabc123abcz")
	}

	b.Log(res)
}

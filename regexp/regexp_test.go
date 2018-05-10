package regexp

import (
	"strings"
	"testing"
)

func TestCompile(t *testing.T) {
	ResetCache()
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
	ResetCache()

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

func TestCompilePOSIX(t *testing.T) {
	ResetCache()
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
	ResetCache()

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

func TestMustCompile(t *testing.T) {
	ResetCache()
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
	ResetCache()

	b.ReportAllocs()

	var rx *Regexp

	for i := 0; i < b.N; i++ {
		rx = MustCompile("^abc.*$")
	}

	b.Log(rx)
}

func TestMustCompilePOSIX(t *testing.T) {
	ResetCache()
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
	ResetCache()
	b.ReportAllocs()

	var rx *Regexp

	for i := 0; i < b.N; i++ {
		rx = MustCompilePOSIX("^abc.*$")
	}

	b.Log(rx)
}

func TestMatchString(t *testing.T) {
	ResetCache()
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

func TestMatchStringFailed(t *testing.T) {
	ResetCache()
	_, err := MatchString("*", "abcedfxyz")
	if err == nil {
		t.Error("Expected error")
	}
}

func TestMatchStringRegexpNotSet(t *testing.T) {
	ResetCache()
	rx := Regexp{}
	matched := rx.MatchString("abcdefxyz")
	if matched {
		t.Error("Expected not to match")
	}
}

func BenchmarkRegExpMatchString(b *testing.B) {
	ResetCache()
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

func TestMatch(t *testing.T) {
	ResetCache()
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

func TestMatchFailed(t *testing.T) {
	ResetCache()
	_, err := Match("*", []byte("abcdefxyz"))
	if err == nil {
		t.Error("Expected error")
	}
}

func TestMatchRegexpNotSet(t *testing.T) {
	ResetCache()
	rx := Regexp{}
	matched := rx.Match([]byte("abcdefxyz"))
	if matched {
		t.Error("Expected not to match")
	}
}

func BenchmarkRegExpMatch(b *testing.B) {
	ResetCache()

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

func TestString(t *testing.T) {
	rx, err := Compile("^abc.*$")
	if err != nil {
		t.Fatal(err)
	}
	if rx.String() != "^abc.*$" {
		t.Error("String didn't match to compiled regexp expression")
	}
}

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

func TestReplaceAllString(t *testing.T) {
	ResetCache()
	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr != "qwe123xyz" {
		t.Error("Eexpected 'qwe123xyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr2 != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr2)
	}
}

func TestReplaceAllStringRegexpNotSet(t *testing.T) {
	ResetCache()
	rx := &Regexp{}
	newStr := rx.ReplaceAllString("qweabcxyz", "123")
	if newStr != "" {
		t.Error("Expected empty string")
	}
}

func BenchmarkRegexpReplaceAllString(b *testing.B) {
	b.ReportAllocs()

	ResetCache()

	rx := MustCompile("abc")
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.ReplaceAllString("qweabcxyz", "123")
	}

	b.Log(str)

}

func TestReplaceAllLiteralString(t *testing.T) {
	ResetCache()
	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr != "qwe123xyz" {
		t.Error("Eexpected 'qwe123xyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr2 != "qwe123xyz" {
		t.Error("Expected 'qwe123xyz'. Got:", newStr2)
	}
}

func TestReplaceAllLiteralStringRegexpNotSet(t *testing.T) {
	ResetCache()
	rx := &Regexp{}
	newStr := rx.ReplaceAllLiteralString("qweabcxyz", "123")
	if newStr != "" {
		t.Error("Expected empty string")
	}
}

func BenchmarkRegexpReplaceAllLiteralString(b *testing.B) {
	b.ReportAllocs()

	ResetCache()

	rx := MustCompile("abc")
	str := ""

	for i := 0; i < b.N; i++ {
		str = rx.ReplaceAllLiteralString("qweabcxyz", "123")
	}

	b.Log(str)

}

func TestReplaceAllStringFunc(t *testing.T) {
	ResetCache()

	f := func(s string) string {
		return strings.ToUpper(s)
	}

	// 1st miss
	rx := MustCompile("abc")
	newStr := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr != "qweABCxyz" {
		t.Error("Eexpected 'qweABCxyz'. Got:", newStr)
	}
	// 2nd hit
	newStr2 := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr2 != "qweABCxyz" {
		t.Error("Expected 'qweABCxyz'. Got:", newStr2)
	}
}

func TestReplaceAllStringFuncRegexpNotSet(t *testing.T) {
	ResetCache()

	f := func(s string) string {
		return strings.ToUpper(s)
	}

	rx := &Regexp{}
	newStr := rx.ReplaceAllStringFunc("qweabcxyz", f)
	if newStr != "" {
		t.Error("Expected empty string returned")
	}
}

func BenchmarkReplaceAllStringFunc(b *testing.B) {
	b.ReportAllocs()

	ResetCache()

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

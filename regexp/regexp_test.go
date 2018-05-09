package regexp

import "testing"

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

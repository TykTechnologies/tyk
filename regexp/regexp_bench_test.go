package regexp

import (
	"fmt"
	"testing"
)

// BenchmarkRegexp_MatchString_Hit measures the end-to-end Tyk wrapper
// hot-path lookup cost when the pattern is cached.
func BenchmarkRegexp_MatchString_Hit(b *testing.B) {
	Reset(true)
	const pattern = "^abc.*$"
	if _, err := Compile(pattern); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ok, _ := MatchString(pattern, "abcxyz"); !ok {
			b.Fatal("expected match")
		}
	}
}

// BenchmarkRegexp_Compile_Hit measures the cost of a cache hit on Compile.
func BenchmarkRegexp_Compile_Hit(b *testing.B) {
	Reset(true)
	const pattern = "^abc.*$"
	if _, err := Compile(pattern); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(pattern); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegexp_Compile_Miss measures the cold-compile cost (each call a
// distinct pattern bypassing the cache).
func BenchmarkRegexp_Compile_Miss(b *testing.B) {
	Reset(true)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(fmt.Sprintf("^miss-%d-.*$", i)); err != nil {
			b.Fatal(err)
		}
	}
}

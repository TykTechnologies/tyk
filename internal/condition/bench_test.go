package condition

import (
	"net/http/httptest"
	"testing"
)

func BenchmarkEval_Method(b *testing.B) {
	fn, _ := Compile(`request.method == "GET"`)
	r := httptest.NewRequest("GET", "/", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(r, nil)
	}
}

func BenchmarkEval_Header(b *testing.B) {
	fn, _ := Compile(`request.headers["X-Test"] == "val"`)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", "val")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(r, nil)
	}
}

func BenchmarkEval_Path(b *testing.B) {
	fn, _ := Compile(`request.path == "/api/v1"`)
	r := httptest.NewRequest("GET", "/api/v1", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(r, nil)
	}
}

func BenchmarkEval_PathRegex(b *testing.B) {
	fn, _ := Compile(`request.path matches "^/api/v[0-9]+"`)
	r := httptest.NewRequest("GET", "/api/v1", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(r, nil)
	}
}

func BenchmarkEval_Complex(b *testing.B) {
	fn, _ := Compile(`request.method == "POST" && request.path contains "/api" && request.headers["X-Flag"] == "on"`)
	r := httptest.NewRequest("POST", "/api/v1", nil)
	r.Header.Set("X-Flag", "on")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(r, nil)
	}
}

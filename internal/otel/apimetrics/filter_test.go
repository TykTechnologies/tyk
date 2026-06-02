package apimetrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompiledFilter_Nil(t *testing.T) {
	var f *CompiledFilter
	assert.True(t, f.Match("any-api", "GET", 200), "nil filter should match everything")
	assert.True(t, f.Match("", "", 0), "nil filter should match zero values")
}

func TestCompiledFilter_NilInput(t *testing.T) {
	f := CompileFilter(nil)
	assert.Nil(t, f, "CompileFilter(nil) should return nil")
}

func TestCompiledFilter_EmptyFilter(t *testing.T) {
	f := CompileFilter(&MetricFilters{})
	assert.NotNil(t, f, "CompileFilter with empty MetricFilters should return non-nil")
	assert.True(t, f.Match("any-api", "GET", 200), "empty filter should match everything")
}

func TestCompiledFilter_APIIDs(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		APIIDs: []string{"api-1", "api-2"},
	})

	assert.True(t, f.Match("api-1", "GET", 200), "should match api-1")
	assert.True(t, f.Match("api-2", "POST", 500), "should match api-2")
	assert.False(t, f.Match("api-3", "GET", 200), "should reject api-3")
	assert.False(t, f.Match("", "GET", 200), "should reject empty API ID")
}

func TestCompiledFilter_Methods(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		Methods: []string{"GET", "POST"},
	})

	assert.True(t, f.Match("any", "GET", 200), "should match GET")
	assert.True(t, f.Match("any", "POST", 200), "should match POST")
	assert.False(t, f.Match("any", "PUT", 200), "should reject PUT")
	assert.False(t, f.Match("any", "DELETE", 200), "should reject DELETE")
}

func TestCompiledFilter_MethodsNormalizedAtCompile(t *testing.T) {
	// CompileFilter uppercases methods at compile time.
	// Match expects callers to pass uppercase methods (as net/http provides).
	f := CompileFilter(&MetricFilters{
		Methods: []string{"get", "Post"},
	})

	assert.True(t, f.Match("any", "GET", 200), "config 'get' should match caller GET")
	assert.True(t, f.Match("any", "POST", 200), "config 'Post' should match caller POST")
	assert.False(t, f.Match("any", "post", 200), "lowercase caller method should not match")
	assert.False(t, f.Match("any", "Put", 200), "mixed-case caller method should not match")
}

func TestCompiledFilter_StatusCodes_Exact(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		StatusCodes: []string{"200", "404"},
	})

	assert.True(t, f.Match("any", "GET", 200), "should match 200")
	assert.True(t, f.Match("any", "GET", 404), "should match 404")
	assert.False(t, f.Match("any", "GET", 201), "should reject 201")
	assert.False(t, f.Match("any", "GET", 500), "should reject 500")
}

func TestCompiledFilter_StatusCodes_ClassPattern(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		StatusCodes: []string{"2xx", "5xx"},
	})

	assert.True(t, f.Match("any", "GET", 200), "should match 200 via 2xx")
	assert.True(t, f.Match("any", "GET", 201), "should match 201 via 2xx")
	assert.True(t, f.Match("any", "GET", 299), "should match 299 via 2xx")
	assert.True(t, f.Match("any", "GET", 500), "should match 500 via 5xx")
	assert.True(t, f.Match("any", "GET", 503), "should match 503 via 5xx")
	assert.False(t, f.Match("any", "GET", 400), "should reject 400")
	assert.False(t, f.Match("any", "GET", 301), "should reject 301")
}

func TestCompiledFilter_StatusCodes_Mixed(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		StatusCodes: []string{"200", "4xx"},
	})

	assert.True(t, f.Match("any", "GET", 200), "should match exact 200")
	assert.True(t, f.Match("any", "GET", 400), "should match 400 via 4xx")
	assert.True(t, f.Match("any", "GET", 404), "should match 404 via 4xx")
	assert.False(t, f.Match("any", "GET", 201), "should reject 201")
	assert.False(t, f.Match("any", "GET", 500), "should reject 500")
}

func TestCompiledFilter_Combined(t *testing.T) {
	f := CompileFilter(&MetricFilters{
		APIIDs:      []string{"api-1"},
		Methods:     []string{"GET", "POST"},
		StatusCodes: []string{"2xx"},
	})

	// All conditions match.
	assert.True(t, f.Match("api-1", "GET", 200), "all conditions match")

	// API ID mismatch.
	assert.False(t, f.Match("api-2", "GET", 200), "wrong API ID")

	// Method mismatch.
	assert.False(t, f.Match("api-1", "DELETE", 200), "wrong method")

	// Status code mismatch.
	assert.False(t, f.Match("api-1", "GET", 500), "wrong status code")
}

func TestStatusCodeMatcher_Matches(t *testing.T) {
	tests := []struct {
		name    string
		matcher statusCodeMatcher
		code    int
		want    bool
	}{
		{"exact match", statusCodeMatcher{exact: 200}, 200, true},
		{"exact mismatch", statusCodeMatcher{exact: 200}, 201, false},
		{"class 2xx match 200", statusCodeMatcher{class: "2xx"}, 200, true},
		{"class 2xx match 299", statusCodeMatcher{class: "2xx"}, 299, true},
		{"class 2xx reject 300", statusCodeMatcher{class: "2xx"}, 300, false},
		{"class 5xx match 500", statusCodeMatcher{class: "5xx"}, 500, true},
		{"class 5xx match 503", statusCodeMatcher{class: "5xx"}, 503, true},
		{"class 5xx reject 400", statusCodeMatcher{class: "5xx"}, 400, false},
		{"class 4xx match 404", statusCodeMatcher{class: "4xx"}, 404, true},
		{"class 1xx match 100", statusCodeMatcher{class: "1xx"}, 100, true},
		{"class 3xx match 301", statusCodeMatcher{class: "3xx"}, 301, true},
		{"empty matcher", statusCodeMatcher{}, 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.matcher.matches(tt.code))
		})
	}
}

func BenchmarkCompiledFilter_Match(b *testing.B) {
	f := CompileFilter(&MetricFilters{
		APIIDs:      []string{"api-1", "api-2", "api-3"},
		Methods:     []string{"GET", "POST"},
		StatusCodes: []string{"2xx", "4xx"},
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Match("api-1", "GET", 200)
	}
}

func BenchmarkCompiledFilter_Match_NilFilter(b *testing.B) {
	var f *CompiledFilter

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Match("api-1", "GET", 200)
	}
}

func BenchmarkCompileFilter(b *testing.B) {
	mf := &MetricFilters{
		APIIDs:      []string{"api-1", "api-2", "api-3"},
		Methods:     []string{"GET", "POST", "PUT"},
		StatusCodes: []string{"200", "201", "2xx", "4xx", "5xx"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileFilter(mf)
	}
}

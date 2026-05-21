package httputil_test

import (
	"fmt"
	"testing"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// BenchmarkPreparePathRegexp_Hit measures hot-path lookup cost when the
// prepared pattern is already cached.
func BenchmarkPreparePathRegexp_Hit(b *testing.B) {
	httputil.ConfigurePathRegexpCache(5000, false, nil)

	const n = 100
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		keys[i] = fmt.Sprintf("/route-%d/{id}", i)
		httputil.PreparePathRegexp(keys[i], true, false)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = httputil.PreparePathRegexp(keys[i%n], true, false)
	}
}

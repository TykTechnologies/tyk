package gateway

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/require"
)

func BenchmarkPrepareRequestToLog_Clone(b *testing.B) {

	a := APISpec{APIDefinition: &apidef.APIDefinition{}}
	a.Proxy.ListenPath = "/listen/"
	a.Proxy.StripListenPath = true

	var err error
	a.target, err = url.Parse("http://upstream.com/base")
	require.NoError(b, err)

	ctx := b.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://proxy.com/listen/get%20it", nil)
	require.NoError(b, err)

	prepareReq := func() *http.Request {
		r := req.WithContext(ctx)
		r.URL.Path = "/listen/get it"
		r.URL.RawPath = "/listen/get%20it"

		return r
	}

	b.Run("clone", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = a.PrepareRequestToLog(prepareReq())
		}
	})

	b.Run("shallow_clone", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = a.PrepareRequestToLogShallowClone(prepareReq())
		}
	})

	b.Run("in_places", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			a.PrepareRequestToLogInPlace(prepareReq())
		}
	})
}

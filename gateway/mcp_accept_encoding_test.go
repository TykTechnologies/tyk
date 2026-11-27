package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestrictMCPAcceptEncoding(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{in: "gzip, deflate, br", want: "gzip, deflate"},
		{in: "br;q=1.0, gzip;q=0.8, zstd, *;q=0.1", want: "gzip;q=0.8"},
		{in: "br, zstd", want: "identity"},
		{in: "*", want: "identity"},
		{in: "identity", want: "identity"},
		{in: "GZIP, x-gzip;q=0.5", want: "GZIP, x-gzip;q=0.5"},
	} {
		h := http.Header{"Accept-Encoding": {tc.in}}
		restrictMCPAcceptEncoding(h)
		assert.Equal(t, tc.want, h.Get("Accept-Encoding"), tc.in)
	}
	h := http.Header{}
	restrictMCPAcceptEncoding(h)
	assert.Empty(t, h.Values("Accept-Encoding"), "an absent header stays absent")
}

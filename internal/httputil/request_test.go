package httputil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func TestTransferEncoding(t *testing.T) {
	checkTransferEncoding := func(in []string) bool {
		return httputil.HasTransferEncoding(&http.Request{
			TransferEncoding: in,
		})
	}

	assert.True(t, checkTransferEncoding([]string{"something-else"}))
	assert.True(t, checkTransferEncoding([]string{"chunked"}))
	assert.False(t, checkTransferEncoding([]string{}))
	assert.False(t, checkTransferEncoding(nil))

	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)
	assert.False(t, httputil.IsGrpcStreaming(r))
}

package httputil_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/internal/httputil"

	"github.com/stretchr/testify/assert"
)

func TestIsTransferEncodingChunked(t *testing.T) {
	isTransferEncodingChunked := func(in []string) bool {
		return httputil.IsTransferEncodingChunked(&http.Request{
			TransferEncoding: in,
		})
	}

	assert.False(t, isTransferEncodingChunked([]string{"something-else"}))
	assert.True(t, isTransferEncodingChunked([]string{"chunked"}))
	assert.False(t, isTransferEncodingChunked([]string{}))
	assert.False(t, isTransferEncodingChunked(nil))
}

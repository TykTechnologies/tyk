package gateway

import (
	"bytes"
	"compress/flate"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeMCPResponseBody(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	var raw bytes.Buffer
	fw, err := flate.NewWriter(&raw, flate.BestSpeed)
	require.NoError(t, err)
	_, err = fw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, fw.Close())

	for name, tc := range map[string]struct {
		encoding string
		body     []byte
	}{
		"gzip":          {"gzip", encodeFakeBody(t, "gzip", payload)},
		"x-gzip":        {"x-gzip", encodeFakeBody(t, "gzip", payload)},
		"deflate, zlib": {"deflate", encodeFakeBody(t, "deflate", payload)},
		"deflate, raw":  {"deflate", raw.Bytes()},
		"identity":      {"identity", payload},
		"none":          {"", payload},
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := decodeMCPResponseBody(tc.encoding, tc.body, 0)
			require.NoError(t, err)
			assert.Equal(t, payload, decoded)
		})
	}

	t.Run("unsupported encoding", func(t *testing.T) {
		_, err := decodeMCPResponseBody("br", []byte("x"), 0)
		assert.ErrorIs(t, err, errUnsupportedContentEncoding)
	})
	t.Run("decoded size is bounded", func(t *testing.T) {
		_, err := decodeMCPResponseBody("gzip", encodeFakeBody(t, "gzip", payload), 8)
		assert.ErrorIs(t, err, errDecodedBodyTooLarge)
	})
	t.Run("corrupt gzip", func(t *testing.T) {
		_, err := decodeMCPResponseBody("gzip", []byte("not gzip"), 0)
		assert.Error(t, err)
	})
}

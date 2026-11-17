package gateway

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSETapFilteringRejectsUnsafeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{
		{"oversized incomplete", "data: " + strings.Repeat("x", maxInputBufferSize), errFilteredSSETooLarge},
		{"oversized complete", "data: " + strings.Repeat("x", maxInputBufferSize) + "\n\n", errFilteredSSETooLarge},
		{"truncated", `data: {"jsonrpc":"2.0","result":{"tools":[`, io.ErrUnexpectedEOF},
		{"truncated after complete", "data: {}\n\ndata: secret", io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tap := NewSSETap(io.NopCloser(strings.NewReader(tc.body)), &MCPListFilterSSEHook{})
			defer tap.Close()
			data, err := io.ReadAll(tap)
			require.ErrorIs(t, err, tc.want)
			require.NotContains(t, string(data), "secret")
			require.Less(t, len(data), 100)
			_, err = tap.Read(make([]byte, 1))
			require.ErrorIs(t, err, tc.want)
		})
		t.Run(tc.name+" unfiltered", func(t *testing.T) {
			tap := NewSSETap(io.NopCloser(strings.NewReader(tc.body)))
			defer tap.Close()
			data, err := io.ReadAll(tap)
			require.NoError(t, err)
			require.Equal(t, tc.body, string(data))
		})
	}
}

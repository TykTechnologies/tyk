package mcpadapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPath string
		wantOK   bool
	}{
		{
			name:     "canonical mcp path",
			target:   "tyk://rest-1/mcp",
			wantHost: "rest-1",
			wantPath: "/mcp",
			wantOK:   true,
		},
		{
			name:     "id-prefixed target with trailing slash",
			target:   "tyk://id:rest-1/mcp/",
			wantHost: "rest-1",
			wantPath: "/mcp/",
			wantOK:   true,
		},
		{
			name:     "fallback adapter host",
			target:   "tyk://rest-1__mcp-server",
			wantHost: "rest-1__mcp-server",
			wantOK:   true,
		},
		{
			name:     "trims surrounding whitespace",
			target:   " tyk://rest-1/mcp ",
			wantHost: "rest-1",
			wantPath: "/mcp",
			wantOK:   true,
		},
		{
			name:     "ignores query and fragment",
			target:   "tyk://rest-1/mcp?foo=bar#section",
			wantHost: "rest-1",
			wantPath: "/mcp",
			wantOK:   true,
		},
		{
			name:   "rejects non tyk scheme",
			target: "http://rest-1/mcp",
		},
		{
			name:   "rejects empty host",
			target: "tyk:///mcp",
		},
		{
			name:   "rejects empty id-prefixed host",
			target: "tyk://id:/mcp",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, path, ok := ParseTarget(tt.target)

			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestAdapterTargetHelpers(t *testing.T) {
	t.Parallel()

	assert.True(t, IsLoopPath("/mcp"))
	assert.True(t, IsLoopPath("/mcp/"))
	assert.False(t, IsLoopPath("/not-mcp"))

	assert.True(t, IsAPIID("rest-1__mcp-server"))
	assert.False(t, IsAPIID("__mcp-server"))
	assert.Equal(t, "rest-1", SourceAPIID("rest-1__mcp-server"))
	assert.Empty(t, SourceAPIID("rest-1"))
}

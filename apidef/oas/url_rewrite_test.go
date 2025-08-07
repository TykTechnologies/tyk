package oas

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

//go:embed testdata/urlRewrite-*.json
var urlRewriteFS embed.FS

func TestURLRewrite_Fill(t *testing.T) {
	var (
		native apidef.URLRewriteMeta
		oasDef URLRewrite
	)

	decode(t, urlRewriteFS, &native, "testdata/urlRewrite-native.json")
	decode(t, urlRewriteFS, &oasDef, "testdata/urlRewrite-oas.json")

	filled := URLRewrite{}
	filled.Fill(native)

	oasDef.Sort()

	assert.Equal(t, oasDef, filled)
}

func TestURLRewrite_ExtractTo(t *testing.T) {
	var (
		native apidef.URLRewriteMeta
		oasDef URLRewrite
	)

	decode(t, urlRewriteFS, &native, "testdata/urlRewrite-native.json")
	decode(t, urlRewriteFS, &oasDef, "testdata/urlRewrite-oas.json")

	extracted := apidef.URLRewriteMeta{}
	oasDef.ExtractTo(&extracted)

	assert.Equal(t, native, extracted)
}


func decode(tb testing.TB, fs embed.FS, dest any, filename string) {
	tb.Helper()

	f, err := fs.ReadFile(filename)
	require.NoError(tb, err)

	err = json.Unmarshal(f, dest)
	require.NoError(tb, err)
}

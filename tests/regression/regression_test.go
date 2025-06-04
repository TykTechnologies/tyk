package regression

import (
	"bytes"
	"embed"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
)

var (
	//go:embed testdata/*
	testdata embed.FS
)

func LoadAPISpec(tb testing.TB, filename string) *gateway.APISpec {
	tb.Helper()

	data := LoadFile(tb, filename)

	apidef := &apidef.APIDefinition{}
	err := json.Unmarshal(data, apidef)
	require.NoError(tb, err, "Error decoding API Definition: %s", filename)

	return &gateway.APISpec{
		APIDefinition: apidef,
	}
}

func TestLoadAPISpec(t *testing.T) {
	f := LoadAPISpec(t, "testdata/issue-10104-apidef.json")

	assert.Equal(t, f.APIDefinition.Proxy.TargetURL, "http://127.0.0.1:3123/")
}

func LoadFile(tb testing.TB, filename string) []byte {
	tb.Helper()

	data, err := testdata.ReadFile(filename)

	httpbin := os.Getenv("HTTPBIN_IMAGE")
	if httpbin == "" {
		httpbin = "127.0.0.1:3123"
	}
	replacement := []byte("//" + httpbin)

	// auto replace from public to private endpoint, part of CI env
	data = bytes.ReplaceAll(data, []byte("//httpbin.org"), replacement)
	data = bytes.ReplaceAll(data, []byte("//google.com"), replacement)

	require.NoError(tb, err, "Error reading file: %s", filename)

	return data
}

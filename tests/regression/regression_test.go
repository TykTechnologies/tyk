package regression

import (
	"embed"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
)

var (
	//go:embed testdata/*
	testdata embed.FS
)

func loadAPISpec(tb testing.TB, filename string) *gateway.APISpec {
	tb.Helper()

	data := loadFile(tb, filename)

	apidef := &apidef.APIDefinition{}
	err := json.Unmarshal(data, apidef)
	require.NoError(tb, err, "Error decoding API Definition: %s", filename)

	// auto replace from public to private endpoint, part of CI env
	apidef.Proxy.ListenPath = strings.ReplaceAll(apidef.Proxy.ListenPath, "httpbin.org", "127.0.0.1:3123")

	return &gateway.APISpec{
		APIDefinition: apidef,
	}
}

func loadFile(tb testing.TB, filename string) []byte {
	tb.Helper()

	data, err := testdata.ReadFile(filename)
	require.NoError(tb, err, "Error reading file: %s", filename)

	return data
}
